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
    - 接着 4 字节：版本号（u32，小端）
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
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

/// 文件容器版本：结构变更时用于兼容/迁移。
const FILE_CIPHER_VERSION: u32 = 1;

/// 文件容器魔数：用于快速判断是否为本软件生成的 `.encrypted` 文件。
const FILE_MAGIC: &[u8; 4] = b"ETEN";

/// 分块大小：1 MiB。
/// - 说明：不是“最终最优值”，但足够在大文件场景下避免内存暴涨。
const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// AEAD tag 长度（AES-GCM 与 ChaCha20-Poly1305 均为 16 字节）。
const AEAD_TAG_SIZE: usize = 16;

/// 解密失败时统一提示（需求强约束）。
const DECRYPT_FAIL_MSG: &str = "密钥错误或数据已损坏";

/// 文件加密 Header（JSON 自描述容器）：
/// - `kind` 用于区分不同算法/模式。
/// - 所有二进制字段统一使用 Base64。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileCipherHeader {
    /// 对称分块加密：AES-256 / ChaCha20
    SymmetricStream {
        v: u32,
        alg: String,
        chunk_size: u32,
        file_size: u64,
        original_file_name: String,
        original_extension: String,
        nonce_prefix_b64: String,
    },

    /// RSA 混合分块加密：RSA 包裹会话密钥 + 数据流对称分块
    HybridRsaStream {
        v: u32,
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
        v: u32,
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
            FileCipherHeader::HybridRsaStream { data_alg, .. } => data_alg,
            FileCipherHeader::HybridX25519Stream { data_alg, .. } => data_alg,
        }
    }

    /// 获取 header 内的文件大小（解密时用于计算分块边界与进度）。
    pub fn file_size(&self) -> u64 {
        match self {
            FileCipherHeader::SymmetricStream { file_size, .. } => *file_size,
            FileCipherHeader::HybridRsaStream { file_size, .. } => *file_size,
            FileCipherHeader::HybridX25519Stream { file_size, .. } => *file_size,
        }
    }

    /// 获取 header 内的 chunk_size。
    pub fn chunk_size(&self) -> u32 {
        match self {
            FileCipherHeader::SymmetricStream { chunk_size, .. } => *chunk_size,
            FileCipherHeader::HybridRsaStream { chunk_size, .. } => *chunk_size,
            FileCipherHeader::HybridX25519Stream { chunk_size, .. } => *chunk_size,
        }
    }

    /// 获取原始文件名（用于解密还原输出文件名）。
    pub fn original_file_name(&self) -> &str {
        match self {
            FileCipherHeader::SymmetricStream { original_file_name, .. } => original_file_name,
            FileCipherHeader::HybridRsaStream { original_file_name, .. } => original_file_name,
            FileCipherHeader::HybridX25519Stream { original_file_name, .. } => original_file_name,
        }
    }

    /// 获取原始扩展名（用于满足需求：加密文件内部保存原扩展名）。
    /// 获取 nonce_prefix（8 字节）。
    pub fn nonce_prefix(&self) -> Result<[u8; 8], String> {
        let s = match self {
            FileCipherHeader::SymmetricStream { nonce_prefix_b64, .. } => nonce_prefix_b64,
            FileCipherHeader::HybridRsaStream { nonce_prefix_b64, .. } => nonce_prefix_b64,
            FileCipherHeader::HybridX25519Stream { nonce_prefix_b64, .. } => nonce_prefix_b64,
        };

        let bytes = B64.decode(s.trim()).map_err(|e| format!("nonce_prefix 解码失败：{e}"))?;
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
    Symmetric { alg: String, key_32: Zeroizing<[u8; 32]> },

    /// RSA 公钥：用于包裹会话密钥（文件数据仍然对称流式）
    RsaPublic { alg: String, public_pem: String },

    /// X25519 接收方公钥：用于协商共享密钥并派生会话密钥
    X25519Public { public_32: [u8; 32] },
}

/// 给文件解密提供的“解密侧密钥”。
#[derive(Debug, Clone)]
pub enum DecryptKeyMaterial {
    /// 对称密钥：用于 AES-256 / ChaCha20
    Symmetric { alg: String, key_32: Zeroizing<[u8; 32]> },

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
pub fn build_decrypt_output_path(header: &FileCipherHeader, output_dir: &Path) -> Result<PathBuf, String> {
    let name = header.original_file_name().trim();
    if name.is_empty() {
        return Err("加密文件缺少原始文件名".to_string());
    }
    Ok(output_dir.join(name))
}

/// 读取 `.encrypted` 文件 header（用于解密前的校验、以及输出路径推导）。
pub fn read_header_only(encrypted_path: &Path) -> Result<FileCipherHeader, String> {
    let f = File::open(encrypted_path).map_err(|e| format!("打开文件失败：{e}"))?;
    let mut r = BufReader::new(f);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(|e| format!("读取文件头失败：{e}"))?;
    if &magic != FILE_MAGIC {
        return Err("不是有效的 .encrypted 文件（魔数不匹配）".to_string());
    }

    let v = read_u32_le(&mut r).map_err(|e| format!("读取版本号失败：{e}"))?;
    if v != FILE_CIPHER_VERSION {
        return Err(format!("不支持的加密文件版本：{v}"));
    }

    let header_len = read_u32_le(&mut r).map_err(|e| format!("读取 header 长度失败：{e}"))?;
    let mut buf = vec![0u8; header_len as usize];
    r.read_exact(&mut buf).map_err(|e| format!("读取 header 失败：{e}"))?;

    let header: FileCipherHeader = serde_json::from_slice(&buf).map_err(|e| format!("解析 header 失败：{e}"))?;
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

        // ========== 根据 key 决定 header 与“数据侧 key” ==========
        let (header, data_key_32): (FileCipherHeader, Zeroizing<[u8; 32]>) = match key {
            EncryptKeyMaterial::Symmetric { alg, key_32 } => {
                let header = FileCipherHeader::SymmetricStream {
                    v: FILE_CIPHER_VERSION,
                    alg,
                    chunk_size: DEFAULT_CHUNK_SIZE,
                    file_size: total,
                    original_file_name,
                    original_extension,
                    nonce_prefix_b64,
                };
                (header, key_32)
            }
            EncryptKeyMaterial::RsaPublic { alg, public_pem } => {
                // 混合加密：会话密钥随机生成，数据侧固定使用 AES-256（与文本页一致）。
                let mut session_key = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(session_key.as_mut());

                let pub_key = RsaPublicKey::from_public_key_pem(public_pem.trim())
                    .map_err(|e| format!("RSA 公钥解析失败：{e}"))?;

                let wrapped = pub_key
                    .encrypt(&mut OsRng, Oaep::new::<Sha256>(), session_key.as_ref())
                    .map_err(|e| format!("RSA 包裹会话密钥失败：{e}"))?;

                let header = FileCipherHeader::HybridRsaStream {
                    v: FILE_CIPHER_VERSION,
                    alg,
                    data_alg: "AES-256".to_string(),
                    chunk_size: DEFAULT_CHUNK_SIZE,
                    file_size: total,
                    original_file_name,
                    original_extension,
                    nonce_prefix_b64,
                    wrapped_key_b64: B64.encode(wrapped),
                };

                (header, session_key)
            }
            EncryptKeyMaterial::X25519Public { public_32 } => {
                // 混合加密：X25519 共享密钥 → HKDF 派生会话密钥，数据侧固定使用 AES-256（与文本页一致）。
                let recipient_pub = X25519PublicKey::from(public_32);

                // 生成临时密钥对（发送方）。
                let eph_secret = X25519StaticSecret::random_from_rng(OsRng);
                let eph_public = X25519PublicKey::from(&eph_secret);
                let shared = eph_secret.diffie_hellman(&recipient_pub);

                // HKDF 盐：使用“第 0 块 nonce（12字节）”，与文本页的做法对齐（nonce 作为 salt）。
                let nonce0 = make_nonce_12(&nonce_prefix, 0);
                let hk = Hkdf::<Sha256>::new(Some(&nonce0), shared.as_bytes());
                let mut derived = Zeroizing::new([0u8; 32]);
                hk.expand(b"encryption-tool:file:v1", derived.as_mut())
                    .map_err(|_| "HKDF 派生失败".to_string())?;

                let header = FileCipherHeader::HybridX25519Stream {
                    v: FILE_CIPHER_VERSION,
                    alg: "X25519".to_string(),
                    data_alg: "AES-256".to_string(),
                    chunk_size: DEFAULT_CHUNK_SIZE,
                    file_size: total,
                    original_file_name,
                    original_extension,
                    nonce_prefix_b64,
                    eph_public_b64: B64.encode(eph_public.as_bytes()),
                };

                (header, derived)
            }
        };

        // ========== 写文件头 ==========
        out.write_all(FILE_MAGIC).map_err(|e| format!("写入魔数失败：{e}"))?;
        write_u32_le(&mut out, FILE_CIPHER_VERSION).map_err(|e| format!("写入版本号失败：{e}"))?;

        let header_json = serde_json::to_vec(&header).map_err(|e| format!("序列化 header 失败：{e}"))?;
        write_u32_le(&mut out, header_json.len() as u32).map_err(|e| format!("写入 header 长度失败：{e}"))?;
        out.write_all(&header_json).map_err(|e| format!("写入 header 失败：{e}"))?;

        // ========== 流式分块加密 ==========
        // 注意：这里把 nonce_prefix 提前解码/固定下来，避免每块重复 Base64 解码造成额外开销。
        let nonce_prefix_bytes = nonce_prefix;

        let mut input = BufReader::new(File::open(input_path).map_err(|e| format!("打开输入文件失败：{e}"))?);
        let mut processed: u64 = 0;
        let chunk_size = DEFAULT_CHUNK_SIZE as usize;

        let mut buf = vec![0u8; chunk_size];
        let mut counter: u32 = 0;

        // 初始进度：让 UI 立刻显示 0%。
        on_progress(0, total);

        loop {
            if is_canceled() {
                return Ok(FileCryptoOutcome::Canceled);
            }

            let n = input.read(&mut buf).map_err(|e| format!("读取输入文件失败：{e}"))?;
            if n == 0 {
                break;
            }

            let nonce = make_nonce_12(&nonce_prefix_bytes, counter);
            counter = counter.wrapping_add(1);

            // 分块 AEAD：每块都有自己的 tag，从而具备“逐块防篡改”能力。
            let ct = aead_encrypt(header.data_alg(), &data_key_32, &nonce, &buf[..n])?;
            out.write_all(&ct).map_err(|e| format!("写入输出文件失败：{e}"))?;

            processed = processed.saturating_add(n as u64);
            on_progress(processed, total);
        }

        out.flush().map_err(|e| format!("写入输出文件失败：{e}"))?;
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
        r.read_exact(&mut magic).map_err(|e| format!("读取文件头失败：{e}"))?;
        if &magic != FILE_MAGIC {
            return Err("不是有效的 .encrypted 文件（魔数不匹配）".to_string());
        }

        let v = read_u32_le(&mut r).map_err(|e| format!("读取版本号失败：{e}"))?;
        if v != FILE_CIPHER_VERSION {
            return Err(format!("不支持的加密文件版本：{v}"));
        }

        let header_len = read_u32_le(&mut r).map_err(|e| format!("读取 header 长度失败：{e}"))?;
        let mut buf = vec![0u8; header_len as usize];
        r.read_exact(&mut buf).map_err(|e| format!("读取 header 失败：{e}"))?;
        let header: FileCipherHeader = serde_json::from_slice(&buf).map_err(|e| format!("解析 header 失败：{e}"))?;

        // ========== 算法匹配校验 ==========
        let file_alg = match &header {
            FileCipherHeader::SymmetricStream { alg, .. } => alg.as_str(),
            FileCipherHeader::HybridRsaStream { alg, .. } => alg.as_str(),
            FileCipherHeader::HybridX25519Stream { alg, .. } => alg.as_str(),
        };

        if expected_algorithm.trim() != file_alg {
            return Err("所选算法与加密文件不匹配".to_string());
        }

        // ========== 准备数据侧 key ==========
        let data_key_32: Zeroizing<[u8; 32]> = match (header.clone(), key) {
            (FileCipherHeader::SymmetricStream { alg, .. }, DecryptKeyMaterial::Symmetric { alg: k_alg, key_32 }) => {
                if alg != k_alg {
                    return Err("所选密钥与算法不匹配".to_string());
                }
                key_32
            }
            (FileCipherHeader::HybridRsaStream { wrapped_key_b64, .. }, DecryptKeyMaterial::RsaPrivate { private_pem }) => {
                let priv_key = RsaPrivateKey::from_pkcs8_pem(private_pem.trim())
                    .map_err(|e| format!("RSA 私钥解析失败：{e}"))?;

                let wrapped = B64.decode(wrapped_key_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
                let session = priv_key
                    .decrypt(Oaep::new::<Sha256>(), &wrapped)
                    .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

                if session.len() != 32 {
                    return Err(DECRYPT_FAIL_MSG.to_string());
                }
                let mut out_key = Zeroizing::new([0u8; 32]);
                out_key.copy_from_slice(&session);
                out_key
            }
            (FileCipherHeader::HybridX25519Stream { eph_public_b64, nonce_prefix_b64, .. }, DecryptKeyMaterial::X25519Secret { secret_32 }) => {
                let eph_pub_bytes = B64.decode(eph_public_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
                if eph_pub_bytes.len() != 32 {
                    return Err(DECRYPT_FAIL_MSG.to_string());
                }
                let mut eph_pub_arr = [0u8; 32];
                eph_pub_arr.copy_from_slice(&eph_pub_bytes);
                let eph_pub = X25519PublicKey::from(eph_pub_arr);

                // nonce_prefix 是 8 字节，构造 nonce0（12 字节）作为 HKDF salt。
                let np = B64.decode(nonce_prefix_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
                if np.len() != 8 {
                    return Err(DECRYPT_FAIL_MSG.to_string());
                }
                let mut np8 = [0u8; 8];
                np8.copy_from_slice(&np);

                let nonce0 = make_nonce_12(&np8, 0);

                // Zeroizing<[u8;32]> 的 `as_ref()` 在某些实现中会退化为 `[u8]` 切片，
                // 这里显式拷贝到定长数组，确保满足 `StaticSecret: From<[u8; 32]>` 的约束。
                let mut sec_arr = [0u8; 32];
                sec_arr.copy_from_slice(secret_32.as_ref());
                let secret = X25519StaticSecret::from(sec_arr);
                let shared = secret.diffie_hellman(&eph_pub);
                let hk = Hkdf::<Sha256>::new(Some(&nonce0), shared.as_bytes());
                let mut derived = Zeroizing::new([0u8; 32]);
                hk.expand(b"encryption-tool:file:v1", derived.as_mut())
                    .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
                derived
            }
            _ => return Err("所选密钥与加密文件类型不匹配".to_string()),
        };

        // ========== 流式分块解密 ==========
        let total = header.file_size();
        let chunk_size = header.chunk_size() as u64;
        let nonce_prefix = header.nonce_prefix().map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

        let mut processed: u64 = 0;
        let mut counter: u32 = 0;

        // 初始进度：让 UI 立刻显示 0%。
        on_progress(0, total);

        while processed < total {
            if is_canceled() {
                return Ok(FileCryptoOutcome::Canceled);
            }

            let remaining = total - processed;
            let plain_len = std::cmp::min(chunk_size, remaining) as usize;
            let ct_len = plain_len + AEAD_TAG_SIZE;

            let mut ct = vec![0u8; ct_len];
            r.read_exact(&mut ct).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

            let nonce = make_nonce_12(&nonce_prefix, counter);
            counter = counter.wrapping_add(1);

            let pt = aead_decrypt(header.data_alg(), &data_key_32, &nonce, &ct).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if pt.len() != plain_len {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            out.write_all(&pt).map_err(|e| format!("写入输出文件失败：{e}"))?;

            processed = processed.saturating_add(plain_len as u64);
            on_progress(processed, total);
        }

        out.flush().map_err(|e| format!("写入输出文件失败：{e}"))?;
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
fn aead_encrypt(alg: &str, key_32: &[u8; 32], nonce_12: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
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
fn aead_decrypt(alg: &str, key_32: &[u8; 32], nonce_12: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
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
