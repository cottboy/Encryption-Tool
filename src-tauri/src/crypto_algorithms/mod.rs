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

/// 算法需要的“密钥输入字段”声明：用于前端按声明动态生成输入表单。
///
/// 说明：
/// - 当前 KeyStore 的 API（UpsertKeyRequest / KeyDetail）仍是“固定字段结构”，
///   因此这里的 field 也限定为既有字段名：
///   - symmetric_key_b64
///   - rsa_public_pem / rsa_private_pem
///   - x25519_public_b64 / x25519_secret_b64
/// - 未来如果要支持“任意算法任意字段”，需要同时升级 KeyStore 的数据模型与 API；
///   但本次目标是：先把 UI 的“按算法写死 if/else”消除，改为按声明渲染。
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct KeyFieldSpec {
    /// 对应前端/后端请求中的字段名（固定集合）。
    pub field: &'static str,
    /// i18n 翻译 key：用于 label，例如 "keys.ui.preview.publicPem"。
    pub label_key: &'static str,
    /// i18n 翻译 key：用于 placeholder（可选）。
    pub placeholder_key: Option<&'static str>,
    /// textarea 行数（当前 UI 都是多行输入）。
    pub rows: u8,
    /// i18n 翻译 key：用于字段下方提示（可选）。
    pub hint_key: Option<&'static str>,
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
    /// 密钥输入字段声明：用于“按声明动态生成输入表单”。
    pub key_fields: &'static [KeyFieldSpec],
}

/// 返回所有算法的 spec（单一来源）。
pub fn all_specs() -> &'static [AlgorithmSpec] {
    &[
        aes256::SPEC,
        chacha20::SPEC,
        rsa2048::SPEC,
        rsa4096::SPEC,
        x25519::SPEC,
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
/// - RSA2048 与 RSA4096 的区别只在于密钥位数，因此这里做一次分发即可。
pub fn generate_rsa_keypair_pem(algorithm: &str) -> Result<(String, String), String> {
    match algorithm.trim() {
        "RSA2048" => rsa2048::generate_keypair_pem(),
        "RSA4096" => rsa4096::generate_keypair_pem(),
        _ => Err(format!("不支持的 RSA 算法：{algorithm}")),
    }
}

/// 生成 X25519 密钥对（Base64）。
pub fn generate_x25519_keypair_b64() -> (String, String) {
    x25519::generate_keypair_b64()
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
        "RSA2048" => rsa2048::text_encrypt(entry, plaintext),
        "RSA4096" => rsa4096::text_encrypt(entry, plaintext),
        "X25519" => x25519::text_encrypt(entry, plaintext),
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
        "RSA2048" => rsa2048::text_decrypt(entry, payload),
        "RSA4096" => rsa4096::text_decrypt(entry, payload),
        "X25519" => x25519::text_decrypt(entry, payload),
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
            _ => Err(format!("不支持的数据算法：{alg}")),
        },
        EncryptKeyMaterial::RsaPublic { alg, public_pem } => match alg.as_str() {
            "RSA2048" => rsa2048::file_encrypt_prepare(public_pem, meta),
            "RSA4096" => rsa4096::file_encrypt_prepare(public_pem, meta),
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
        FileCipherHeader::HybridRsaStream {
            alg,
            wrapped_key_b64,
            ..
        } => match key {
            DecryptKeyMaterial::RsaPrivate { private_pem } => match alg.as_str() {
                "RSA2048" => rsa2048::file_decrypt_unwrap_data_key(wrapped_key_b64, &private_pem),
                "RSA4096" => rsa4096::file_decrypt_unwrap_data_key(wrapped_key_b64, &private_pem),
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
    /// 文件容器版本号（用于 header.v）。
    pub version: u32,
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
