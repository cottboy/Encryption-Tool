/*
  RSA4096 算法实现（文本 + 文件）。

  用户约束：
  - RSA2048 / RSA4096 视为两种“完全独立的算法文件”
  - 不引入 rsa_common.rs 之类的共享实现文件

  说明：
  - 逻辑与 rsa2048.rs 基本一致；区别在于“生成密钥”时使用 4096 位。
*/

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::{TextCipherPayload, TEXT_CIPHER_VERSION};

pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: "RSA4096",
    category: AlgorithmCategory::Asymmetric,
    encrypt_needs: "加密需要公钥（PEM）；解密需要私钥（PEM）；长文本/文件走混合加密",
    decrypt_needs: "解密需要私钥（PEM）",
    key_fields: &[
        crate::crypto_algorithms::KeyFieldSpec {
            field: "rsa_public_pem",
            label_key: "keys.ui.preview.publicPem",
            placeholder_key: Some("keys.ui.placeholders.rsaPublicPem"),
            rows: 8,
            hint_key: None,
        },
        crate::crypto_algorithms::KeyFieldSpec {
            field: "rsa_private_pem",
            label_key: "keys.ui.preview.privatePem",
            placeholder_key: Some("keys.ui.placeholders.rsaPrivatePem"),
            rows: 10,
            hint_key: None,
        },
    ],
};

fn rsa_oaep_max_len(pub_key: &RsaPublicKey) -> usize {
    let k = pub_key.size();
    k.saturating_sub(2 * 32 + 2)
}

fn parse_rsa_public(entry: &keystore::KeyEntry) -> Result<RsaPublicKey, String> {
    match &entry.material {
        keystore::KeyMaterial::RsaPrivate { public_pem, .. } => {
            let pem = public_pem
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "RSA 加密需要公钥：该条目仅包含私钥".to_string())?;
            RsaPublicKey::from_public_key_pem(pem).map_err(|e| format!("RSA 公钥解析失败：{e}"))
        }
        keystore::KeyMaterial::RsaPublic { public_pem } => {
            RsaPublicKey::from_public_key_pem(public_pem.trim())
                .map_err(|e| format!("RSA 公钥解析失败：{e}"))
        }
        _ => Err("密钥类型不匹配：需要 RSA".to_string()),
    }
}

fn parse_rsa_private(entry: &keystore::KeyEntry) -> Result<RsaPrivateKey, String> {
    match &entry.material {
        keystore::KeyMaterial::RsaPrivate { private_pem, .. } => {
            RsaPrivateKey::from_pkcs8_pem(private_pem.trim())
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 生成 RSA4096 密钥对（PKCS8 私钥 PEM + SPKI 公钥 PEM）。
pub fn generate_keypair_pem() -> Result<(String, String), String> {
    let private = RsaPrivateKey::new(&mut OsRng, 4096).map_err(|e| format!("RSA 生成失败：{e}"))?;
    let public = RsaPublicKey::from(&private);

    let private_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
        .to_string();

    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
        .to_string();

    Ok((private_pem, public_pem))
}

pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    let pub_key = parse_rsa_public(entry)?;
    let padding = Oaep::new::<Sha256>();
    let max_len = rsa_oaep_max_len(&pub_key);

    if plaintext.len() <= max_len {
        let ct = pub_key
            .encrypt(&mut OsRng, padding, plaintext)
            .map_err(|_| "加密失败".to_string())?;

        Ok((
            TextCipherPayload::RsaOaep {
                v: TEXT_CIPHER_VERSION,
                alg: "RSA4096".to_string(),
                ciphertext_b64: B64.encode(ct),
            },
            false,
        ))
    } else {
        let mut session_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(session_key.as_mut());

        let nonce = super::utils::random_nonce_12();
        let data_ct =
            super::aes256::text_encrypt_with_session_key(&session_key, &nonce, plaintext)?;

        let wrapped = pub_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), session_key.as_ref())
            .map_err(|_| "加密失败".to_string())?;

        Ok((
            TextCipherPayload::HybridRsa {
                v: TEXT_CIPHER_VERSION,
                alg: "RSA4096".to_string(),
                data_alg: "AES-256".to_string(),
                nonce_b64: B64.encode(nonce),
                wrapped_key_b64: B64.encode(wrapped),
                ciphertext_b64: B64.encode(data_ct),
            },
            true,
        ))
    }
}

pub fn text_decrypt(
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    match payload {
        TextCipherPayload::RsaOaep {
            alg,
            ciphertext_b64,
            ..
        } => {
            if alg != "RSA4096" {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }
            let priv_key = parse_rsa_private(entry)?;
            let ct = B64
                .decode(ciphertext_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            priv_key
                .decrypt(Oaep::new::<Sha256>(), &ct)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())
        }
        TextCipherPayload::HybridRsa {
            alg,
            data_alg,
            nonce_b64,
            wrapped_key_b64,
            ciphertext_b64,
            ..
        } => {
            if alg != "RSA4096" {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }
            if data_alg != "AES-256" {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }

            let priv_key = parse_rsa_private(entry)?;
            let wrapped = B64
                .decode(wrapped_key_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let session_key = priv_key
                .decrypt(Oaep::new::<Sha256>(), &wrapped)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            if session_key.len() != 32 {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }
            let mut key_32 = Zeroizing::new([0u8; 32]);
            key_32.copy_from_slice(&session_key);

            let nonce = super::utils::decode_b64_12("nonce", &nonce_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let ct = B64
                .decode(ciphertext_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;

            super::aes256::text_decrypt_with_session_key(&key_32, &nonce, &ct)
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

pub fn file_encrypt_prepare(
    public_pem: String,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, Zeroizing<[u8; 32]>), String> {
    let mut session_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(session_key.as_mut());

    let pub_key = RsaPublicKey::from_public_key_pem(public_pem.trim())
        .map_err(|e| format!("RSA 公钥解析失败：{e}"))?;
    let wrapped = pub_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), session_key.as_ref())
        .map_err(|e| format!("RSA 包裹会话密钥失败：{e}"))?;

    let header = FileCipherHeader::HybridRsaStream {
        v: meta.version,
        alg: "RSA4096".to_string(),
        data_alg: "AES-256".to_string(),
        chunk_size: meta.chunk_size,
        file_size: meta.file_size,
        original_file_name: meta.original_file_name,
        original_extension: meta.original_extension,
        nonce_prefix_b64: meta.nonce_prefix_b64,
        wrapped_key_b64: B64.encode(wrapped),
    };

    Ok((header, session_key))
}

pub fn file_decrypt_unwrap_data_key(
    wrapped_key_b64: &str,
    private_pem: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let priv_key = RsaPrivateKey::from_pkcs8_pem(private_pem.trim())
        .map_err(|_| crate::file_crypto::DECRYPT_FAIL_MSG.to_string())?;
    let wrapped = B64
        .decode(wrapped_key_b64.trim())
        .map_err(|_| crate::file_crypto::DECRYPT_FAIL_MSG.to_string())?;
    let session_key = priv_key
        .decrypt(Oaep::new::<Sha256>(), &wrapped)
        .map_err(|_| crate::file_crypto::DECRYPT_FAIL_MSG.to_string())?;
    if session_key.len() != 32 {
        return Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&session_key);
    Ok(out)
}
