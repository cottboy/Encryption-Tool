/*
  文件加密/解密核心（Rust 后端执行）：
  - 需求要求（来自 `需求文档.md`）：
    1) 输出扩展名统一使用 `.encrypted`
    2) 加密文件内部必须保存：原始文件名、原始扩展名、算法/参数信息（用于解密还原）
    3) 文件场景必须支持大文件：流式分块处理，避免一次性读入内存
    4) RSA / X25519 在文件场景一律走混合加密（只包裹会话密钥，数据仍用对称流式处理）
    5) 解密失败（选错密钥或文件被篡改）必须提示：密钥错误或数据已损坏

  设计说明（本阶段最小可用实现）：
  - `.encrypted` 文件格式：一个“自描述容器”：
    - 前 4 字节：魔数 "ETEN"
    - 接着 4 字节：Header JSON 的字节长度（u32，小端）
    - 接着：Header JSON（UTF-8）
    - 最后：密文数据流（按 chunk_size 分块，每块使用 AEAD 独立加密并附带 tag）
  - 分块加密策略（避免引入额外 streaming 依赖）：
    - 每块使用 AEAD（AES-256-GCM 或 ChaCha20-Poly1305）独立加密
    - 生成 8 字节随机 nonce_prefix；每块 nonce = nonce_prefix(8) + counter(u32, big-endian)
    - Header 中保存 nonce_prefix 与 chunk_size、原始文件大小
  - 混合加密策略：
    - RSA：随机生成 32 字节会话密钥 → RSA-OAEP 包裹 → 数据流用会话密钥做 AEAD 分块
    - X25519：生成临时密钥对 → 与接收方公钥计算共享密钥 → HKDF 派生会话密钥 → 数据流用会话密钥做 AEAD 分块
*/

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// 文件容器魔数：用于快速判断是否为本软件生成的 `.encrypted` 文件。
const FILE_MAGIC: &[u8; 4] = b"ETEN";

/// 分块大小：1 MiB。
/// - 说明：不是“最终最优值”，但足够在大文件场景下避免内存暴涨。
const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// 进度回调间隔：每处理多少字节才回调一次进度（避免事件发送过于频繁）。
/// - 说明：设置为 10 MiB，对于大文件可以显著减少事件数量，同时保持进度条流畅。
const PROGRESS_CALLBACK_INTERVAL: u64 = 10 * 1024 * 1024;

/// AEAD tag 长度（AES-GCM 与 ChaCha20-Poly1305 均为 16 字节）。
const AEAD_TAG_SIZE: usize = 16;

/// 解密失败时统一提示（需求强约束）。
pub(crate) const DECRYPT_FAIL_MSG: &str = "密钥错误或数据已损坏";

/// `.encrypted` 文件中 Header(JSON) 的最大允许长度（字节）。
///
/// 为什么需要这个上限：
/// - Header 长度字段是从文件里读出来的，如果文件被篡改/恶意构造，长度可能被改成非常大；
/// - 如果我们不设上限就直接 `vec![0; header_len]`，程序会尝试分配巨量内存，轻则报错，重则崩溃/被系统杀掉；
/// - Header 本质上只包含少量元数据（算法、nonce 前缀、原始文件名等），正常情况下远小于 1 MiB。
///
/// 取值策略：
/// - 设为 10 MiB：给未来 header 增加字段留余量，同时仍能有效防止“超大声明”导致的 OOM。
const MAX_HEADER_JSON_LEN: u32 = 10 * 1024 * 1024;

/// 文件加密 Header（JSON 自描述容器）：
/// - `kind` 用于区分不同算法/模式。
/// - 所有二进制字段统一使用 Base64。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileCipherHeader {
    /// 对称分块加密：AES-256 / ChaCha20
    SymmetricStream {
        alg: String,
        chunk_size: u32,
        file_size: u64,
        original_file_name: String,
        original_extension: String,
        nonce_prefix_b64: String,
    },

    /// 会话分块加密：由“外部会话密钥（32字节）”直接作为数据侧 key。
    /// - 当前用于：ML-KEM-768 一次封装建立会话后，对文本/文件复用同一把会话密钥。
    SessionStream {
        alg: String,
        data_alg: String,
        chunk_size: u32,
        file_size: u64,
        original_file_name: String,
        original_extension: String,
        nonce_prefix_b64: String,
    },

    /// RSA 混合分块加密：RSA 包裹会话密钥 + 数据流对称分块
    HybridRsaStream {
        alg: String,
        data_alg: String,
        chunk_size: u32,
        file_size: u64,
        original_file_name: String,
        original_extension: String,
        nonce_prefix_b64: String,
        wrapped_key_b64: String,
    },

    /// X25519 混合分块加密：X25519 协商/封装 + 数据流对称分块
    HybridX25519Stream {
        alg: String,
        data_alg: String,
        chunk_size: u32,
        file_size: u64,
        original_file_name: String,
        original_extension: String,
        nonce_prefix_b64: String,
        eph_public_b64: String,
    },
}

impl FileCipherHeader {
    /// 读取 header 内声明的“对称数据算法”：
    /// - 对称模式：就是 `alg`
    /// - 混合模式：使用 `data_alg`（当前固定 AES-256）
    pub fn data_alg(&self) -> &str {
        match self {
            FileCipherHeader::SymmetricStream { alg, .. } => alg,
            FileCipherHeader::SessionStream { data_alg, .. } => data_alg,
            FileCipherHeader::HybridRsaStream { data_alg, .. } => data_alg,
            FileCipherHeader::HybridX25519Stream { data_alg, .. } => data_alg,
        }
    }

    /// 获取 header 内的文件大小（解密时用于计算分块边界与进度）。
    pub fn file_size(&self) -> u64 {
        match self {
            FileCipherHeader::SymmetricStream { file_size, .. } => *file_size,
            FileCipherHeader::SessionStream { file_size, .. } => *file_size,
            FileCipherHeader::HybridRsaStream { file_size, .. } => *file_size,
            FileCipherHeader::HybridX25519Stream { file_size, .. } => *file_size,
        }
    }

    /// 获取 header 内的 chunk_size。
    pub fn chunk_size(&self) -> u32 {
        match self {
            FileCipherHeader::SymmetricStream { chunk_size, .. } => *chunk_size,
            FileCipherHeader::SessionStream { chunk_size, .. } => *chunk_size,
            FileCipherHeader::HybridRsaStream { chunk_size, .. } => *chunk_size,
            FileCipherHeader::HybridX25519Stream { chunk_size, .. } => *chunk_size,
        }
    }

    /// 获取原始文件名（用于解密还原输出文件名）。
    pub fn original_file_name(&self) -> &str {
        match self {
            FileCipherHeader::SymmetricStream {
                original_file_name, ..
            } => original_file_name,
            FileCipherHeader::SessionStream {
                original_file_name, ..
            } => original_file_name,
            FileCipherHeader::HybridRsaStream {
                original_file_name, ..
            } => original_file_name,
            FileCipherHeader::HybridX25519Stream {
                original_file_name, ..
            } => original_file_name,
        }
    }

    /// 获取原始扩展名（用于满足需求：加密文件内部保存原扩展名）。
    /// 获取 nonce_prefix（8 字节）。
    pub fn nonce_prefix(&self) -> Result<[u8; 8], String> {
        let s = match self {
            FileCipherHeader::SymmetricStream {
                nonce_prefix_b64, ..
            } => nonce_prefix_b64,
            FileCipherHeader::SessionStream {
                nonce_prefix_b64, ..
            } => nonce_prefix_b64,
            FileCipherHeader::HybridRsaStream {
                nonce_prefix_b64, ..
            } => nonce_prefix_b64,
            FileCipherHeader::HybridX25519Stream {
                nonce_prefix_b64, ..
            } => nonce_prefix_b64,
        };

        let bytes = B64
            .decode(s.trim())
            .map_err(|e| format!("nonce_prefix 解码失败：{e}"))?;
        if bytes.len() != 8 {
            return Err("nonce_prefix 长度不正确".to_string());
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// 文件加密任务：用于区分“正常结束 / 被取消”。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCryptoOutcome {
    Completed,
    Canceled,
}

/// 给文件加密提供的“加密侧密钥”。
/// - 说明：这里不直接依赖 keystore 结构，保持模块边界清晰。
#[derive(Debug, Clone)]
pub enum EncryptKeyMaterial {
    /// 对称密钥：用于 AES-256 / ChaCha20
    Symmetric {
        alg: String,
        key_32: Zeroizing<[u8; 32]>,
    },

    /// RSA 公钥：用于包裹会话密钥（文件数据仍然对称流式）
    RsaPublic { alg: String, public_pem: String },

    /// X25519 接收方公钥：用于协商共享密钥并派生会话密钥
    X25519Public { public_32: [u8; 32] },
}

/// 给文件解密提供的“解密侧密钥”。
#[derive(Debug, Clone)]
pub enum DecryptKeyMaterial {
    /// 对称密钥：用于 AES-256 / ChaCha20
    Symmetric {
        alg: String,
        key_32: Zeroizing<[u8; 32]>,
    },

    /// RSA 私钥：用于解包会话密钥（文件数据仍然对称流式）
    RsaPrivate { private_pem: String },

    /// X25519 私钥：用于复原共享密钥并派生会话密钥
    X25519Secret { secret_32: Zeroizing<[u8; 32]> },
}

/// 根据输入文件与输出目录，生成“加密输出路径”：
/// - 规则：原文件名后追加 `.encrypted`（保证扩展名统一为 `.encrypted`）。
pub fn build_encrypt_output_path(input_path: &Path, output_dir: &Path) -> Result<PathBuf, String> {
    let file_name = input_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "无法解析输入文件名".to_string())?;

    Ok(output_dir.join(format!("{file_name}.encrypted")))
}

/// 根据 `.encrypted` 文件 header 与输出目录，生成“解密输出路径”：
/// - 规则：还原 header 中记录的原始文件名。
pub fn build_decrypt_output_path(
    header: &FileCipherHeader,
    output_dir: &Path,
) -> Result<PathBuf, String> {
    // 说明：
    // - 正常情况下 header.original_file_name 来自加密时的 `input_path.file_name()`，应当是“纯文件名”；
    // - 但解密输入文件可能来自外部（下载/他人发送/被篡改），header 里的 original_file_name 可能被恶意改成：
    //   - 含路径分隔符（例如 `..\\..\\xxx` / `../../xxx`）→ 典型路径穿越；
    //   - 绝对路径（例如 `C:\\...` / `/etc/...`）→ 试图把输出写到非预期位置；
    // - 因此这里做“最基础、最保守”的防护：只允许纯文件名，否则统一回退为固定安全名。
    let safe_name = sanitize_decrypt_output_file_name(header);
    Ok(output_dir.join(safe_name))
}

/// 将 header 中声明的“原始文件名”净化为可安全落盘的文件名。
///
/// 规则（按你的需求）：
/// - 如果是“纯文件名”（不包含目录/驱动器/路径穿越语义），则原样使用；
/// - 否则一律改成固定的 `"safe_filename"`。
///
/// 注意：
/// - 这里不做“智能修复”（比如取最后一段 basename），因为那可能仍会被构造出迷惑性名字；
/// - 固定名字更简单、更安全，也满足你提出的“检测到就改成 safe filename”。
pub fn sanitize_decrypt_output_file_name(header: &FileCipherHeader) -> String {
    sanitize_file_name_or_fallback(header.original_file_name())
}

/// 读取 `.encrypted` 文件 header（用于解密前的校验、以及输出路径推导）。
pub fn read_header_only(encrypted_path: &Path) -> Result<FileCipherHeader, String> {
    let f = File::open(encrypted_path).map_err(|e| format!("打开文件失败：{e}"))?;
    let mut r = BufReader::new(f);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)
        .map_err(|e| format!("读取文件头失败：{e}"))?;
    if &magic != FILE_MAGIC {
        return Err("不是有效的 .encrypted 文件（魔数不匹配）".to_string());
    }

    let header_len = read_u32_le(&mut r).map_err(|e| format!("读取 header 长度失败：{e}"))?;
    // 关键防护：限制 header 长度，避免恶意文件导致巨量内存分配（OOM/崩溃）。
    let header_len_usize = checked_header_len(header_len)?;
    let mut buf = vec![0u8; header_len_usize];
    r.read_exact(&mut buf)
        .map_err(|e| format!("读取 header 失败：{e}"))?;

    let header: FileCipherHeader =
        serde_json::from_slice(&buf).map_err(|e| format!("解析 header 失败：{e}"))?;
    Ok(header)
}

/// 文件加密（流式分块）：
/// - `on_progress(processed, total)`：由调用方决定如何上报进度（事件/日志等）
/// - `is_canceled()`：由调用方提供取消信号
pub fn encrypt_file_stream(
    input_path: &Path,
    output_path: &Path,
    key: EncryptKeyMaterial,
    on_progress: &dyn Fn(u64, u64),
    is_canceled: &dyn Fn() -> bool,
) -> Result<FileCryptoOutcome, String> {
    // ========== 基础校验 ==========
    if !input_path.exists() {
        return Err("输入文件不存在".to_string());
    }

    let meta = fs::metadata(input_path).map_err(|e| format!("读取输入文件信息失败：{e}"))?;
    if !meta.is_file() {
        return Err("输入路径不是文件".to_string());
    }
    let total = meta.len();

    // 输出文件采用 create_new：避免误覆盖已有文件（更安全）。
    let out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|e| format!("创建输出文件失败：{e}"))?;

    // 一旦开始写输出文件，如果后续失败/取消，需要删除半成品。
    let mut out = BufWriter::new(out_file);

    let result = (|| -> Result<FileCryptoOutcome, String> {
        // ========== 准备 metadata ==========
        let original_file_name = input_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "无法解析输入文件名".to_string())?
            .to_string();

        let original_extension = input_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        // ========== nonce_prefix（8 字节） ==========
        let mut nonce_prefix = [0u8; 8];
        OsRng.fill_bytes(&mut nonce_prefix);
        let nonce_prefix_b64 = B64.encode(nonce_prefix);

        // ========== 根据算法准备 header 与“数据侧 key” ==========
        // 说明：不同算法的 header 结构与会话密钥生成/包裹方式不同，
        // 这里统一交给 crypto_algorithms（每种算法一个文件）做分发。
        let meta = crate::crypto_algorithms::FileEncryptMeta {
            chunk_size: DEFAULT_CHUNK_SIZE,
            file_size: total,
            original_file_name,
            original_extension,
            nonce_prefix_b64,
            nonce_prefix_8: nonce_prefix,
        };
        let (header, data_key_32): (FileCipherHeader, Zeroizing<[u8; 32]>) =
            crate::crypto_algorithms::file_encrypt_prepare(key, meta)?;

        // ========== 写文件头 ==========
        out.write_all(FILE_MAGIC)
            .map_err(|e| format!("写入魔数失败：{e}"))?;

        let header_json =
            serde_json::to_vec(&header).map_err(|e| format!("序列化 header 失败：{e}"))?;
        write_u32_le(&mut out, header_json.len() as u32)
            .map_err(|e| format!("写入 header 长度失败：{e}"))?;
        out.write_all(&header_json)
            .map_err(|e| format!("写入 header 失败：{e}"))?;

        // ========== 流式分块加密 ==========
        // 注意：这里把 nonce_prefix 提前解码/固定下来，避免每块重复 Base64 解码造成额外开销。
        let nonce_prefix_bytes = nonce_prefix;

        let mut input =
            BufReader::new(File::open(input_path).map_err(|e| format!("打开输入文件失败：{e}"))?);
        let mut processed: u64 = 0;
        let chunk_size = DEFAULT_CHUNK_SIZE as usize;

        let mut buf = vec![0u8; chunk_size];
        let mut counter: u32 = 0;

        // 进度回调节流：记录上次回调时的处理字节数，避免事件发送过于频繁。
        let mut last_progress_report: u64 = 0;

        // 初始进度：让 UI 立刻显示 0%。
        on_progress(0, total);

        loop {
            if is_canceled() {
                return Ok(FileCryptoOutcome::Canceled);
            }

            let n = input
                .read(&mut buf)
                .map_err(|e| format!("读取输入文件失败：{e}"))?;
            if n == 0 {
                break;
            }

            let nonce = make_nonce_12(&nonce_prefix_bytes, counter);
            counter = counter.wrapping_add(1);

            // 分块 AEAD：每块都有自己的 tag，从而具备“逐块防篡改”能力。
            let ct = aead_encrypt(header.data_alg(), &data_key_32, &nonce, &buf[..n])?;
            out.write_all(&ct)
                .map_err(|e| format!("写入输出文件失败：{e}"))?;

            processed = processed.saturating_add(n as u64);

            // 进度回调节流：只有当处理字节数增加超过阈值时才回调，减少事件发送频率。
            // 说明：对于小文件（< 10 MiB）会在循环结束后统一回调最终进度。
            if processed - last_progress_report >= PROGRESS_CALLBACK_INTERVAL {
                on_progress(processed, total);
                last_progress_report = processed;
            }
        }

        out.flush().map_err(|e| format!("写入输出文件失败：{e}"))?;

        // 最终进度：确保 UI 显示 100%（避免因节流导致进度卡在 99%）。
        on_progress(processed, total);

        Ok(FileCryptoOutcome::Completed)
    })();

    match result {
        Ok(FileCryptoOutcome::Completed) => Ok(FileCryptoOutcome::Completed),
        Ok(FileCryptoOutcome::Canceled) => {
            // 用户取消：删除半成品输出文件，避免误以为成功。
            drop(out);
            let _ = fs::remove_file(output_path);
            Ok(FileCryptoOutcome::Canceled)
        }
        Err(e) => {
            // 发生错误：同样删除半成品输出文件。
            drop(out);
            let _ = fs::remove_file(output_path);
            Err(e)
        }
    }
}

/// 文件解密（流式分块）：
/// - 解密失败的核心提示必须收敛为 DECRYPT_FAIL_MSG（需求强约束）
pub fn decrypt_file_stream(
    encrypted_path: &Path,
    output_path: &Path,
    key: DecryptKeyMaterial,
    expected_algorithm: &str,
    on_progress: &dyn Fn(u64, u64),
    is_canceled: &dyn Fn() -> bool,
) -> Result<FileCryptoOutcome, String> {
    // ========== 基础校验 ==========
    if !encrypted_path.exists() {
        return Err("输入文件不存在".to_string());
    }

    // 输出文件采用 create_new：避免误覆盖已有文件（更安全）。
    let out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|e| format!("创建输出文件失败：{e}"))?;

    let mut out = BufWriter::new(out_file);

    let result = (|| -> Result<FileCryptoOutcome, String> {
        let f = File::open(encrypted_path).map_err(|e| format!("打开文件失败：{e}"))?;
        let mut r = BufReader::new(f);

        // ========== 读取头 ==========
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .map_err(|e| format!("读取文件头失败：{e}"))?;
        if &magic != FILE_MAGIC {
            return Err("不是有效的 .encrypted 文件（魔数不匹配）".to_string());
        }

        let header_len = read_u32_le(&mut r).map_err(|e| format!("读取 header 长度失败：{e}"))?;
        // 关键防护：限制 header 长度，避免恶意文件导致巨量内存分配（OOM/崩溃）。
        // 解密场景按需求做错误收敛：一旦发现 header 不可信/异常，统一提示“密钥错误或数据已损坏”。
        let header_len_usize =
            checked_header_len(header_len).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
        let mut buf = vec![0u8; header_len_usize];
        r.read_exact(&mut buf)
            .map_err(|e| format!("读取 header 失败：{e}"))?;
        let header: FileCipherHeader =
            serde_json::from_slice(&buf).map_err(|e| format!("解析 header 失败：{e}"))?;

        // ========== 算法匹配校验 ==========
        let file_alg = match &header {
            FileCipherHeader::SymmetricStream { alg, .. } => alg.as_str(),
            FileCipherHeader::SessionStream { alg, .. } => alg.as_str(),
            FileCipherHeader::HybridRsaStream { alg, .. } => alg.as_str(),
            FileCipherHeader::HybridX25519Stream { alg, .. } => alg.as_str(),
        };

        if expected_algorithm.trim() != file_alg {
            return Err("所选算法与加密文件不匹配".to_string());
        }

        // ========== 准备数据侧 key ==========
        // 先解出 nonce_prefix：
        // - 用于后续分块 nonce 构造
        // - 同时也用于 X25519 的 HKDF salt（nonce0）
        let nonce_prefix = header
            .nonce_prefix()
            .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
        let nonce0 = make_nonce_12(&nonce_prefix, 0);

        // 对称场景：额外校验“所选密钥的算法”与 header.alg 一致（更符合 UI 预期）。
        if let FileCipherHeader::SymmetricStream { alg, .. } = &header {
            match &key {
                DecryptKeyMaterial::Symmetric { alg: k_alg, .. } => {
                    if alg != k_alg {
                        return Err("所选密钥与算法不匹配".to_string());
                    }
                }
                _ => return Err("所选密钥与加密文件类型不匹配".to_string()),
            }
        }

        // 具体“解包/派生会话密钥”的算法差异交给 crypto_algorithms 处理。
        let data_key_32: Zeroizing<[u8; 32]> =
            crate::crypto_algorithms::file_decrypt_unwrap_data_key(&header, key, &nonce0)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

        // ========== 流式分块解密 ==========
        let total = header.file_size();
        let chunk_size = header.chunk_size() as u64;
        // nonce_prefix 已在上面提前解出，这里直接复用。

        // 安全检查：防止恶意文件声明超大 chunk_size 导致内存分配失败。
        // 说明：正常情况下 chunk_size 应该等于 DEFAULT_CHUNK_SIZE (1 MiB)，
        // 这里允许一定的容差（比如未来版本可能调整分块大小），但不允许超过 10 MiB。
        const MAX_ALLOWED_CHUNK_SIZE: u64 = 10 * 1024 * 1024;
        if chunk_size > MAX_ALLOWED_CHUNK_SIZE {
            return Err(DECRYPT_FAIL_MSG.to_string());
        }

        let mut processed: u64 = 0;
        let mut counter: u32 = 0;

        // 进度回调节流：记录上次回调时的处理字节数，避免事件发送过于频繁。
        let mut last_progress_report: u64 = 0;

        // 初始进度：让 UI 立刻显示 0%。
        on_progress(0, total);

        while processed < total {
            if is_canceled() {
                return Ok(FileCryptoOutcome::Canceled);
            }

            let remaining = total - processed;
            let plain_len = std::cmp::min(chunk_size, remaining) as usize;
            let ct_len = plain_len + AEAD_TAG_SIZE;

            // 安全检查：再次确认即将分配的缓冲区大小在合理范围内。
            // 说明：这是防御性编程，避免因整数溢出或其他边界情况导致的内存问题。
            if ct_len > MAX_ALLOWED_CHUNK_SIZE as usize + AEAD_TAG_SIZE {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }

            let mut ct = vec![0u8; ct_len];
            r.read_exact(&mut ct)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

            let nonce = make_nonce_12(&nonce_prefix, counter);
            counter = counter.wrapping_add(1);

            let pt = aead_decrypt(header.data_alg(), &data_key_32, &nonce, &ct)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if pt.len() != plain_len {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            out.write_all(&pt)
                .map_err(|e| format!("写入输出文件失败：{e}"))?;

            processed = processed.saturating_add(plain_len as u64);

            // 进度回调节流：只有当处理字节数增加超过阈值时才回调，减少事件发送频率。
            // 说明：对于小文件（< 10 MiB）会在循环结束后统一回调最终进度。
            if processed - last_progress_report >= PROGRESS_CALLBACK_INTERVAL {
                on_progress(processed, total);
                last_progress_report = processed;
            }
        }

        out.flush().map_err(|e| format!("写入输出文件失败：{e}"))?;

        // 最终进度：确保 UI 显示 100%（避免因节流导致进度卡在 99%）。
        on_progress(processed, total);

        Ok(FileCryptoOutcome::Completed)
    })();

    match result {
        Ok(FileCryptoOutcome::Completed) => Ok(FileCryptoOutcome::Completed),
        Ok(FileCryptoOutcome::Canceled) => {
            drop(out);
            let _ = fs::remove_file(output_path);
            Ok(FileCryptoOutcome::Canceled)
        }
        Err(e) => {
            drop(out);
            let _ = fs::remove_file(output_path);
            Err(e)
        }
    }
}

// =========================
// 下面是“通用工具函数”
// =========================

/// 读取 u32（小端）。
fn read_u32_le(r: &mut dyn Read) -> Result<u32, std::io::Error> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// 校验并转换 `.encrypted` 文件中的 header 长度字段。
///
/// 目的：
/// - 防止恶意/损坏文件将 header_len 改成超大值，导致 `Vec` 分配巨量内存；
/// - 同时避免在不同平台（32/64 位）上 `u32 -> usize` 转换的潜在问题。
fn checked_header_len(header_len: u32) -> Result<usize, String> {
    // 0 长度的 header 没有意义：既无法解析，也说明文件高度异常。
    if header_len == 0 {
        return Err("加密文件 header 长度异常（为 0）".to_string());
    }

    // 上限保护：避免 OOM。
    if header_len > MAX_HEADER_JSON_LEN {
        return Err(format!(
            "加密文件 header 过大（{header_len} 字节），可能已损坏或不安全"
        ));
    }

    // 安全转换：即便未来在 32 位平台编译，也避免溢出/截断隐患。
    usize::try_from(header_len).map_err(|_| "加密文件 header 长度无法转换为平台长度".to_string())
}

/// 判断一个字符串是否为“纯文件名”（不包含路径/盘符/路径穿越语义）。
///
/// 为什么要做这个判断：
/// - header.original_file_name 来自外部输入文件（可能被篡改），不能信任；
/// - 如果允许包含路径分隔符或 `..`，就可能发生路径穿越，把解密输出写到非预期位置。
fn is_pure_file_name(name: &str) -> bool {
    let s = name.trim();
    if s.is_empty() {
        return false;
    }

    // 明确拒绝常见危险字符/语义：
    // - `/`、`\\`：目录分隔符（跨平台）
    // - `:`：Windows 盘符/UNC 等语义的一部分（例如 `C:\`）
    // - `\0`：字符串终止符（部分底层接口会把它当作截断点，风险极高）
    if s.contains('/')
        || s.contains('\\')
        || s.contains(':')
        || s.contains('\0')
        || s == "."
        || s == ".."
    {
        return false;
    }

    // 再用 Path 的组件规则做一次兜底：必须只有一个 Normal 组件。
    let p = Path::new(s);
    let mut components = p.components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => true,
        _ => false,
    }
}

/// 将不可信的文件名净化为安全文件名。
///
/// 规则：
/// - 如果是纯文件名：返回原值（trim 后）；
/// - 否则：返回固定的 `"safe_filename"`。
fn sanitize_file_name_or_fallback(name: &str) -> String {
    let s = name.trim();
    if is_pure_file_name(s) {
        return s.to_string();
    }
    // 按你的需求：检测到“非纯文件名/疑似攻击内容”时，统一改为固定安全文件名。
    "safe filename".to_string()
}

/// 写入 u32（小端）。
fn write_u32_le(w: &mut dyn Write, v: u32) -> Result<(), std::io::Error> {
    w.write_all(&v.to_le_bytes())
}

/// 由 nonce_prefix(8) + counter(u32) 构造 12 字节 nonce。
fn make_nonce_12(prefix8: &[u8; 8], counter: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(prefix8);
    out[8..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// AEAD 分块加密：输入 key(32) + nonce(12) + 明文，输出密文（含 tag）。
fn aead_encrypt(
    alg: &str,
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    match alg {
        "AES-256" => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_32));
            cipher
                .encrypt(AesNonce::from_slice(nonce_12), plaintext)
                .map_err(|_| "加密失败".to_string())
        }
        "ChaCha20" => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key_32));
            cipher
                .encrypt(ChaChaNonce::from_slice(nonce_12), plaintext)
                .map_err(|_| "加密失败".to_string())
        }
        _ => Err(format!("不支持的数据算法：{alg}")),
    }
}

/// AEAD 分块解密：输入 key(32) + nonce(12) + 密文（含 tag），输出明文。
fn aead_decrypt(
    alg: &str,
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    match alg {
        "AES-256" => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_32));
            cipher
                .decrypt(AesNonce::from_slice(nonce_12), ciphertext)
                .map_err(|_| "解密失败".to_string())
        }
        "ChaCha20" => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key_32));
            cipher
                .decrypt(ChaChaNonce::from_slice(nonce_12), ciphertext)
                .map_err(|_| "解密失败".to_string())
        }
        _ => Err(format!("不支持的数据算法：{alg}")),
    }
}
