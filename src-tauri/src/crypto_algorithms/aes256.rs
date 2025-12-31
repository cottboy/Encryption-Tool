/*
  AES-256-GCM 算法实现（文本 + 文件）。

  这里做两件事：
  1) 声明该算法需要什么密钥材料（SPEC）
  2) 提供文本加/解密与文件加密 header 构造所需的具体实现

  设计约束：
  - 文本：使用 AEAD（AES-256-GCM），nonce=12字节随机
  - 文件：使用“分块 AEAD”，nonce_prefix 由 file_crypto 生成；每块 nonce = prefix(8) + counter(u32)
*/

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::{TextCipherPayload, TEXT_CIPHER_VERSION};

use super::utils;

/// AES-256 算法声明：用于 UI 分组、以及后端统一列举支持的算法。
pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: "AES-256",
    category: AlgorithmCategory::Symmetric,
    encrypt_needs: "需要对称密钥（Base64，32字节）",
    decrypt_needs: "需要对称密钥（Base64，32字节）",
    key_fields: &[
        // 对称算法：只需要一段 32 字节密钥（Base64）。
        crate::crypto_algorithms::KeyFieldSpec {
            field: "symmetric_key_b64",
            label_key: "keys.ui.preview.symmetricKey",
            placeholder_key: Some("keys.ui.placeholders.symmetricB64"),
            rows: 5,
            hint_key: None,
        },
    ],
};

/// 解析对称密钥（Base64 32 字节）。
fn parse_symmetric_key(entry: &keystore::KeyEntry) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    match &entry.material {
        keystore::KeyMaterial::Symmetric { key_b64 } => utils::decode_b64_32("对称密钥", key_b64),
        _ => Err("密钥类型不匹配：需要对称密钥".to_string()),
    }
}

/// AES-256-GCM 加密：输入 key(32) + nonce(12) + 明文，输出密文（含 tag）。
fn aead_encrypt(
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_32));
    cipher
        .encrypt(AesNonce::from_slice(nonce_12), plaintext)
        .map_err(|_| "加密失败".to_string())
}

/// AES-256-GCM 解密：输入 key(32) + nonce(12) + 密文（含 tag），输出明文。
fn aead_decrypt(
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_32));
    cipher
        .decrypt(AesNonce::from_slice(nonce_12), ciphertext)
        .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())
}

/// 混合加密的数据侧：使用“会话密钥”做 AES-256-GCM 加密，返回密文（含 tag）。
///
/// 说明：
/// - RSA/X25519 混合加密的 data_alg 当前固定为 AES-256；
/// - 把这段逻辑放在 AES-256 算法文件里，避免在 RSA/X25519 文件里重复写 AEAD 调用。
pub(crate) fn text_encrypt_with_session_key(
    key_32: &zeroize::Zeroizing<[u8; 32]>,
    nonce_12: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    // Zeroizing<[u8;32]> 会 Deref 成 &[u8;32]，这里直接传引用即可。
    aead_encrypt(key_32, nonce_12, plaintext)
}

/// 混合加密的数据侧：使用“会话密钥”做 AES-256-GCM 解密，返回明文。
pub(crate) fn text_decrypt_with_session_key(
    key_32: &zeroize::Zeroizing<[u8; 32]>,
    nonce_12: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    aead_decrypt(key_32, nonce_12, ciphertext)
}

/// 文本加密（AES-256-GCM）。
pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    let key_32 = parse_symmetric_key(entry)?;
    let nonce = utils::random_nonce_12();
    let ct = aead_encrypt(&key_32, &nonce, plaintext)?;

    Ok((
        TextCipherPayload::SymmetricAead {
            v: TEXT_CIPHER_VERSION,
            alg: "AES-256".to_string(),
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ct),
        },
        false,
    ))
}

/// 文本解密（AES-256-GCM）。
pub fn text_decrypt(
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    match payload {
        TextCipherPayload::SymmetricAead {
            alg,
            nonce_b64,
            ciphertext_b64,
            ..
        } => {
            // 防御：容器内声明的算法必须与当前算法一致。
            if alg != "AES-256" {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }

            let key_32 = parse_symmetric_key(entry)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let nonce = utils::decode_b64_12("nonce", &nonce_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let ct = B64
                .decode(ciphertext_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;

            aead_decrypt(&key_32, &nonce, &ct)
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 文件加密：构造 SymmetricStream header，并直接使用用户提供的对称密钥作为数据侧 key。
pub fn file_encrypt_prepare(
    key_32: zeroize::Zeroizing<[u8; 32]>,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, zeroize::Zeroizing<[u8; 32]>), String> {
    let header = FileCipherHeader::SymmetricStream {
        v: meta.version,
        alg: "AES-256".to_string(),
        chunk_size: meta.chunk_size,
        file_size: meta.file_size,
        original_file_name: meta.original_file_name,
        original_extension: meta.original_extension,
        nonce_prefix_b64: meta.nonce_prefix_b64,
    };
    Ok((header, key_32))
}
