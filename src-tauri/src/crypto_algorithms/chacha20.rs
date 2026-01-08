/*
  ChaCha20-Poly1305 算法实现（文本 + 文件）。

  职责同 aes256.rs：
  - 声明密钥材料需求（SPEC）
  - 提供文本加/解密与文件 header 构造
*/

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta, KeyPartSpec};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::TextCipherPayload;

use super::utils;

pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: "ChaCha20",
    category: AlgorithmCategory::Symmetric,
    encrypt_needs_key: "algorithms.needs.ChaCha20.encrypt",
    decrypt_needs_key: "algorithms.needs.ChaCha20.decrypt",
    key_parts: &[KeyPartSpec {
        id: "symmetric_key_b64",
        encoding: keystore::KeyPartEncoding::Base64,
        hidden: false,
        label_key: "keys.ui.preview.symmetricKey",
        placeholder_key: Some("keys.ui.placeholders.symmetricB64"),
        rows: 4,
        hint_key: None,
        required_for_encrypt: true,
        required_for_decrypt: true,
    }],
    normalize_parts,
};

fn parse_symmetric_key(entry: &keystore::KeyEntry) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let part = keystore::find_part(entry, "symmetric_key_b64")
        .ok_or_else(|| "密钥缺少对称密钥（symmetric_key_b64）".to_string())?;
    if part.encoding != keystore::KeyPartEncoding::Base64 {
        return Err("对称密钥的 encoding 必须为 base64".to_string());
    }
    utils::decode_b64_32("对称密钥", &part.value)
}

fn aead_encrypt(
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key_32));
    cipher
        .encrypt(ChaChaNonce::from_slice(nonce_12), plaintext)
        .map_err(|_| "加密失败".to_string())
}

fn aead_decrypt(
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key_32));
    cipher
        .decrypt(ChaChaNonce::from_slice(nonce_12), ciphertext)
        .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())
}

pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    let key_32 = parse_symmetric_key(entry)?;
    let nonce = utils::random_nonce_12();
    let ct = aead_encrypt(&key_32, &nonce, plaintext)?;

    Ok((
        TextCipherPayload::SymmetricAead {
            alg: "ChaCha20".to_string(),
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ct),
        },
        false,
    ))
}

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
            if alg != "ChaCha20" {
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

pub fn file_encrypt_prepare(
    key_32: zeroize::Zeroizing<[u8; 32]>,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, zeroize::Zeroizing<[u8; 32]>), String> {
    let header = FileCipherHeader::SymmetricStream {
        alg: "ChaCha20".to_string(),
        chunk_size: meta.chunk_size,
        file_size: meta.file_size,
        original_file_name: meta.original_file_name,
        original_extension: meta.original_extension,
        nonce_prefix_b64: meta.nonce_prefix_b64,
    };
    Ok((header, key_32))
}

/// 规范化并校验“导入/编辑保存”提交的 parts。
///
/// ChaCha20 仅接受一个 part：symmetric_key_b64（base64，解码后 32 字节）。
fn normalize_parts(parts: Vec<keystore::KeyPart>) -> Result<Vec<keystore::KeyPart>, String> {
    let mut map = utils::collect_parts_unique(parts)?;

    let key_part = map
        .remove("symmetric_key_b64")
        .ok_or_else(|| "缺少对称密钥（symmetric_key_b64）".to_string())?;
    if key_part.encoding != keystore::KeyPartEncoding::Base64 {
        return Err("symmetric_key_b64 的 encoding 必须为 base64".to_string());
    }

    let decoded = B64
        .decode(key_part.value.trim().as_bytes())
        .map_err(|e| format!("Base64 解码失败：{e}"))?;
    if decoded.len() != 32 {
        return Err("对称密钥长度必须为 32 字节（Base64 解码后）".to_string());
    }
    let normalized_b64 = B64.encode(decoded);

    if !map.is_empty() {
        let extra = map.keys().cloned().collect::<Vec<_>>().join(", ");
        return Err(format!("ChaCha20 不支持的字段：{extra}"));
    }

    Ok(vec![keystore::KeyPart {
        id: "symmetric_key_b64".to_string(),
        encoding: keystore::KeyPartEncoding::Base64,
        value: normalized_b64,
    }])
}
