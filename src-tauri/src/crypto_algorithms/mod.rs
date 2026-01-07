/*
  加密算法注册表（Rust 后端）：把“算法是什么 / 需要什么密钥材料 / 如何加解密”集中管理。

  为什么要引入这个模块：
  - 现在项目里对算法的判断大量依赖字符串 match，分散在：
    - commands.rs（算法列表、密钥生成）
    - text_crypto.rs（文本加/解密）
    - file_crypto.rs（文件加/解密、流式分块）
    - 前端页面（算法下拉列表、能力判断）
  - 这会导致“新增算法”必须到处改分支，很容易失控。

  本模块的目标：
  - 一种算法一个文件（例如 rsa2048.rs / rsa4096.rs）
  - 每个算法文件声明自己需要什么密钥材料（AlgorithmSpec）
  - text_crypto / file_crypto / commands 统一通过本模块做算法分发
*/

mod aes256;
mod chacha20;
mod mlkem768;
mod rsa2048;
mod rsa4096;
mod utils;
mod x25519;

use crate::file_crypto::{DecryptKeyMaterial, EncryptKeyMaterial, FileCipherHeader};
use crate::keystore;
use crate::text_crypto::TextCipherPayload;

/// 算法分类：用于 UI 分组展示（对称 / 非对称）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmCategory {
    /// 对称算法：文本/文件都可直接使用同一把对称密钥。
    Symmetric,
    /// 非对称/密钥协商：实际会走混合加密（包裹/协商会话密钥 + 对称 AEAD 加密数据）。
    Asymmetric,
}

/// 算法需要的“密钥零件（parts）”声明：用于前端按声明动态生成输入表单。
///
/// 说明：
/// - KeyStore 已升级为通用 parts 结构（见 keystore.rs），因此这里不再受“固定字段结构体”限制；
/// - 仍然约定：同一个算法在整个产品里使用稳定的 part id（你已确认“命名保持不变”）。
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct KeyPartSpec {
    /// part id：用于前端表单绑定与后端存储（例如 rsa_public_pem）。
    pub id: &'static str,
    /// part 的编码类型：用于前端提示与后端解析（base64/pem/hex/utf8）。
    pub encoding: keystore::KeyPartEncoding,
    /// 是否为“隐藏字段”：不在 UI 表单中展示，但仍会参与 required 判定与持久化。
    pub hidden: bool,
    /// i18n 翻译 key：用于 label，例如 "keys.ui.preview.publicPem"。
    pub label_key: &'static str,
    /// i18n 翻译 key：用于 placeholder（可选）。
    pub placeholder_key: Option<&'static str>,
    /// textarea 行数（当前 UI 都是多行输入）。
    pub rows: u8,
    /// i18n 翻译 key：用于字段下方提示（可选）。
    pub hint_key: Option<&'static str>,
    /// 是否为“加密所必需”的 part：前端据此判断“该密钥能否用于加密”。
    pub required_for_encrypt: bool,
    /// 是否为“解密所必需”的 part：前端据此判断“该密钥能否用于解密”。
    pub required_for_decrypt: bool,
}

/// 单个算法“需要哪些密钥材料”的声明。
///
/// 注意：
/// - 这里的“密钥材料”是对 KeyStore 的输入约束；
/// - 具体验证逻辑仍在各算法实现里（例如 RSA 解密必须有私钥）。
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AlgorithmSpec {
    /// 算法 ID（同时也是 UI 下拉值 / KeyEntry.key_type）。
    pub id: &'static str,
    /// 分类（用于 UI 分组）。
    pub category: AlgorithmCategory,
    /// 加密所需的密钥材料说明（给 UI/业务做预判用）。
    pub encrypt_needs: &'static str,
    /// 解密所需的密钥材料说明（给 UI/业务做预判用）。
    pub decrypt_needs: &'static str,
    /// 密钥零件声明：用于“按声明动态生成输入表单”。
    pub key_parts: &'static [KeyPartSpec],
    /// 将前端提交的 parts 做“算法级规范化/校验”，并返回可落盘的 parts。
    ///
    /// 为什么要放在算法文件里：
    /// - commands.rs 不应为每个算法写 if/else 校验；
    /// - 新增算法时，只需要新增一个算法文件并注册到 all_specs，即可获得完整的“导入/编辑/保存”能力。
    pub normalize_parts: fn(Vec<keystore::KeyPart>) -> Result<Vec<keystore::KeyPart>, String>,
}

/// 返回所有算法的 spec（单一来源）。
pub fn all_specs() -> &'static [AlgorithmSpec] {
    &[
        aes256::SPEC,
        chacha20::SPEC,
        rsa2048::SPEC,
        rsa4096::SPEC,
        x25519::SPEC,
        mlkem768::SPEC,
    ]
}

/// 根据算法 id 查找 spec。
#[allow(dead_code)]
pub fn spec_by_id(id: &str) -> Option<&'static AlgorithmSpec> {
    let id = id.trim();
    all_specs().iter().find(|s| s.id == id)
}

/// 生成 RSA 密钥对（根据算法 id 选择位数）。
///
/// 说明：
/// - RSA-2048 与 RSA-4096 的区别只在于密钥位数，因此这里做一次分发即可。
pub fn generate_rsa_keypair_pem(algorithm: &str) -> Result<(String, String), String> {
    match algorithm.trim() {
        "RSA-2048" => rsa2048::generate_keypair_pem(),
        "RSA-4096" => rsa4096::generate_keypair_pem(),
        _ => Err(format!("不支持的 RSA 算法：{algorithm}")),
    }
}

/// 生成 X25519 密钥对（Base64）。
pub fn generate_x25519_keypair_b64() -> (String, String) {
    x25519::generate_keypair_b64()
}

/// 生成 ML-KEM-768 密钥对（Base64）：secret_b64 + public_b64。
pub fn generate_mlkem768_keypair_b64() -> (String, String) {
    mlkem768::generate_keypair_b64()
}

/// 使用 ML-KEM-768 公钥封装：返回 (封装密钥 ct 的 Base64, 共享密钥 ss(32字节))。
pub fn mlkem768_encapsulate_to_public_b64(
    public_b64: &str,
) -> Result<(String, zeroize::Zeroizing<[u8; 32]>), String> {
    mlkem768::encapsulate_to_public_b64(public_b64)
}

/// 文本加密：根据算法 id 分发到对应算法文件。
pub fn text_encrypt(
    algorithm: &str,
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    match algorithm.trim() {
        "AES-256" => aes256::text_encrypt(entry, plaintext),
        "ChaCha20" => chacha20::text_encrypt(entry, plaintext),
        "RSA-2048" => rsa2048::text_encrypt(entry, plaintext),
        "RSA-4096" => rsa4096::text_encrypt(entry, plaintext),
        "X25519" => x25519::text_encrypt(entry, plaintext),
        "ML-KEM-768" => mlkem768::text_encrypt(entry, plaintext),
        _ => Err("不支持的算法".to_string()),
    }
}

/// 文本解密：根据算法 id 分发到对应算法文件。
pub fn text_decrypt(
    algorithm: &str,
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    match algorithm.trim() {
        "AES-256" => aes256::text_decrypt(entry, payload),
        "ChaCha20" => chacha20::text_decrypt(entry, payload),
        "RSA-2048" => rsa2048::text_decrypt(entry, payload),
        "RSA-4096" => rsa4096::text_decrypt(entry, payload),
        "X25519" => x25519::text_decrypt(entry, payload),
        "ML-KEM-768" => mlkem768::text_decrypt(entry, payload),
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 文件加密（header + 数据侧 key 生成/包裹）：根据 EncryptKeyMaterial 分发到算法文件。
///
/// 说明：
/// - 文件加密本体（流式分块）仍在 file_crypto.rs；
/// - 这里负责“根据算法准备 header + 得到数据侧 32 字节会话密钥”。
pub fn file_encrypt_prepare(
    key: EncryptKeyMaterial,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, zeroize::Zeroizing<[u8; 32]>), String> {
    match key {
        EncryptKeyMaterial::Symmetric { alg, key_32 } => match alg.as_str() {
            "AES-256" => aes256::file_encrypt_prepare(key_32, meta),
            "ChaCha20" => chacha20::file_encrypt_prepare(key_32, meta),
            "ML-KEM-768" => mlkem768::file_encrypt_prepare(key_32, meta),
            _ => Err(format!("不支持的数据算法：{alg}")),
        },
        EncryptKeyMaterial::RsaPublic { alg, public_pem } => match alg.as_str() {
            "RSA-2048" => rsa2048::file_encrypt_prepare(public_pem, meta),
            "RSA-4096" => rsa4096::file_encrypt_prepare(public_pem, meta),
            _ => Err(format!("不支持的算法：{alg}")),
        },
        EncryptKeyMaterial::X25519Public { public_32 } => {
            x25519::file_encrypt_prepare(public_32, meta)
        }
    }
}

/// 文件解密（解包/协商数据侧 key）：根据 header.kind 分发到算法文件。
///
/// 说明：
/// - 这里的返回值是“数据侧 32 字节 key”，用于后续分块 AEAD 解密。
pub fn file_decrypt_unwrap_data_key(
    header: &FileCipherHeader,
    key: DecryptKeyMaterial,
    nonce0_12: &[u8; 12],
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    match header {
        FileCipherHeader::SymmetricStream { alg, .. } => match (alg.as_str(), key) {
            ("AES-256", DecryptKeyMaterial::Symmetric { key_32, .. }) => Ok(key_32),
            ("ChaCha20", DecryptKeyMaterial::Symmetric { key_32, .. }) => Ok(key_32),
            _ => Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string()),
        },
        FileCipherHeader::SessionStream { alg, .. } => match (alg.as_str(), key) {
            ("ML-KEM-768", DecryptKeyMaterial::Symmetric { key_32, .. }) => Ok(key_32),
            _ => Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string()),
        },
        FileCipherHeader::HybridRsaStream {
            alg,
            wrapped_key_b64,
            ..
        } => match key {
            DecryptKeyMaterial::RsaPrivate { private_pem } => match alg.as_str() {
                "RSA-2048" => rsa2048::file_decrypt_unwrap_data_key(wrapped_key_b64, &private_pem),
                "RSA-4096" => rsa4096::file_decrypt_unwrap_data_key(wrapped_key_b64, &private_pem),
                _ => Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string()),
            },
            _ => Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string()),
        },
        FileCipherHeader::HybridX25519Stream { eph_public_b64, .. } => match key {
            DecryptKeyMaterial::X25519Secret { secret_32 } => {
                x25519::file_decrypt_derive_data_key(eph_public_b64, &secret_32, nonce0_12)
            }
            _ => Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string()),
        },
    }
}

/// 文件加密准备阶段需要的元数据：由 file_crypto 负责收集，本模块只负责按算法写入 header。
#[derive(Debug, Clone)]
pub struct FileEncryptMeta {
    /// 分块大小（用于 header.chunk_size）。
    pub chunk_size: u32,
    /// 原文件大小。
    pub file_size: u64,
    /// 原始文件名（不含路径）。
    pub original_file_name: String,
    /// 原始扩展名（可能为空）。
    pub original_extension: String,
    /// nonce_prefix 的 Base64（8 字节）。
    pub nonce_prefix_b64: String,
    /// nonce_prefix 原始字节（8 字节），用于算法（例如 X25519）计算 nonce0。
    pub nonce_prefix_8: [u8; 8],
}
