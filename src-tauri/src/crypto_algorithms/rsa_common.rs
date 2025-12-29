/*
  RSA 公共实现（供 RSA2048 / RSA4096 复用）。

  说明：
  - RSA2048 与 RSA4096 的“加解密逻辑”完全一致，区别只在于密钥生成时的位数。
  - 运行期加密/解密时，实际限制由“密钥本身的模长”决定。
  - 因为用户明确要求：RSA2048 和 RSA4096 分成两个文件，所以这里提供 common，两个文件做薄封装即可。
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

use crate::crypto_algorithms::FileEncryptMeta;
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::{TextCipherPayload, TEXT_CIPHER_VERSION};

/// 计算 RSA-OAEP 可直接加密的最大长度（字节）。
/// - 公式：k - 2*hLen - 2
///   - k：模长（字节）
///   - hLen：哈希长度（SHA-256 为 32）
fn rsa_oaep_max_len(pub_key: &RsaPublicKey) -> usize {
    let k = pub_key.size();
    k.saturating_sub(2 * 32 + 2)
}

/// 解析 RSA 公钥：
/// - 如果条目是私钥：要求同时包含 public_pem（产品允许仅私钥，但仅私钥不能加密）
/// - 如果条目是公钥：直接使用
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

/// 解析 RSA 私钥（仅支持 PKCS8 PEM）。
fn parse_rsa_private(entry: &keystore::KeyEntry) -> Result<RsaPrivateKey, String> {
    match &entry.material {
        keystore::KeyMaterial::RsaPrivate { private_pem, .. } => {
            RsaPrivateKey::from_pkcs8_pem(private_pem.trim())
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 生成 RSA 密钥对（bits=2048/4096），返回 PKCS8 私钥 PEM 与 SPKI 公钥 PEM。
pub fn generate_keypair_pem(bits: usize) -> Result<(String, String), String> {
    let private = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| format!("RSA 生成失败：{e}"))?;
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

/// 文本加密：RSA-OAEP 直接加密（短文本）或混合加密（长文本）。
pub fn text_encrypt(
    alg_id: &str,
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    let pub_key = parse_rsa_public(entry)?;
    let padding = Oaep::new::<Sha256>();
    let max_len = rsa_oaep_max_len(&pub_key);

    if plaintext.len() <= max_len {
        // 直接 RSA-OAEP：仅适用于较短文本（字节级限制）。
        let ct = pub_key
            .encrypt(&mut OsRng, padding, plaintext)
            .map_err(|_| "加密失败".to_string())?;

        Ok((
            TextCipherPayload::RsaOaep {
                v: TEXT_CIPHER_VERSION,
                alg: alg_id.to_string(),
                ciphertext_b64: B64.encode(ct),
            },
            false,
        ))
    } else {
        // 混合加密：随机会话密钥 + AEAD 加密正文；RSA-OAEP 仅包裹会话密钥。
        let mut session_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(session_key.as_mut());

        // data_alg：混合加密的数据侧固定使用 AES-256（与现有实现保持一致）。
        let data_alg = "AES-256";
        let nonce = super::utils::random_nonce_12();
        // data_alg 当前固定为 AES-256；具体 AEAD 调用由 aes256.rs 负责。
        let data_ct =
            super::aes256::text_encrypt_with_session_key(&session_key, &nonce, plaintext)?;

        let wrapped = pub_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), session_key.as_ref())
            .map_err(|_| "加密失败".to_string())?;

        Ok((
            TextCipherPayload::HybridRsa {
                v: TEXT_CIPHER_VERSION,
                alg: alg_id.to_string(),
                data_alg: data_alg.to_string(),
                nonce_b64: B64.encode(nonce),
                wrapped_key_b64: B64.encode(wrapped),
                ciphertext_b64: B64.encode(data_ct),
            },
            true,
        ))
    }
}

/// 文本解密：支持 RSA-OAEP 与 HybridRsa。
pub fn text_decrypt(
    alg_id: &str,
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    match payload {
        TextCipherPayload::RsaOaep {
            alg,
            ciphertext_b64,
            ..
        } => {
            if alg != alg_id {
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
            if alg != alg_id {
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

            // data_alg 当前约定为 AES-256（与现有实现一致），防御性检查避免未来混淆。
            if data_alg != "AES-256" {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }
            super::aes256::text_decrypt_with_session_key(&key_32, &nonce, &ct)
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 文件加密：构造 HybridRsaStream header + 生成会话密钥并用 RSA-OAEP 包裹。
pub fn file_encrypt_prepare(
    alg_id: &str,
    public_pem: String,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, Zeroizing<[u8; 32]>), String> {
    // 会话密钥：随机 32 字节；数据侧固定 AES-256（与文本逻辑保持一致）。
    let mut session_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(session_key.as_mut());

    let pub_key = RsaPublicKey::from_public_key_pem(public_pem.trim())
        .map_err(|e| format!("RSA 公钥解析失败：{e}"))?;
    let wrapped = pub_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), session_key.as_ref())
        .map_err(|e| format!("RSA 包裹会话密钥失败：{e}"))?;

    let header = FileCipherHeader::HybridRsaStream {
        v: meta.version,
        alg: alg_id.to_string(),
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

/// 文件解密：用 RSA 私钥解包 header.wrapped_key_b64，得到数据侧会话密钥（32字节）。
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
