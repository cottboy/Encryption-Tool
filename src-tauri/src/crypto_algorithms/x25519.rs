/*
  X25519（密钥协商/封装）算法实现（文本 + 文件）。

  当前产品规则（与现有实现保持一致）：
  - KeyStore 允许只导入公钥或只导入私钥（用于展示/管理）
  - 但真正进行加/解密时：必须同时具备公钥 + 私钥（“完整”条目）

  加密策略：
  - 文本：生成临时密钥对 → 与接收方公钥做 DH → HKDF 派生会话密钥 → AES-256-GCM 加密正文
    - HKDF salt 使用随机 nonce(12字节)，与现有实现对齐
  - 文件：同样派生会话密钥，但 HKDF salt 使用“第 0 块 nonce”，与 file_crypto 现有实现对齐
*/

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta, KeyPartSpec};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::TextCipherPayload;

use super::utils;

pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: "X25519",
    category: AlgorithmCategory::Asymmetric,
    encrypt_needs: "加/解密都需要同时具备公钥+私钥（Base64，32字节）；文本/文件走混合加密",
    decrypt_needs: "加/解密都需要同时具备公钥+私钥（Base64，32字节）",
    key_parts: &[
        KeyPartSpec {
            id: "x25519_public_b64",
            encoding: keystore::KeyPartEncoding::Base64,
            label_key: "keys.ui.preview.publicB64",
            placeholder_key: Some("keys.ui.placeholders.x25519PublicB64"),
            rows: 4,
            hint_key: None,
            required_for_encrypt: true,
            required_for_decrypt: true,
        },
        KeyPartSpec {
            id: "x25519_secret_b64",
            encoding: keystore::KeyPartEncoding::Base64,
            label_key: "keys.ui.preview.secretB64",
            placeholder_key: Some("keys.ui.placeholders.x25519SecretB64"),
            rows: 4,
            // 产品规则提示：放在“私钥输入框”下方，避免重复展示。
            hint_key: Some("keys.ui.hints.x25519NeedFull"),
            required_for_encrypt: true,
            required_for_decrypt: true,
        },
    ],
    normalize_parts,
};

/// 生成 X25519 密钥对（Base64）：secret_b64 + public_b64。
pub fn generate_keypair_b64() -> (String, String) {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = X25519StaticSecret::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);

    let secret_b64 = B64.encode(secret_bytes);
    let public_b64 = B64.encode(public.as_bytes());
    (secret_b64, public_b64)
}

fn parse_public(entry: &keystore::KeyEntry) -> Result<X25519PublicKey, String> {
    let part = keystore::find_part(entry, "x25519_public_b64")
        .ok_or_else(|| "X25519 缺少公钥".to_string())?;
    if part.encoding != keystore::KeyPartEncoding::Base64 {
        return Err("x25519_public_b64 的 encoding 必须为 base64".to_string());
    }
    let bytes = utils::decode_b64_32("X25519 公钥", &part.value)?;
    Ok(X25519PublicKey::from(*bytes))
}

fn parse_secret(entry: &keystore::KeyEntry) -> Result<X25519StaticSecret, String> {
    let part = keystore::find_part(entry, "x25519_secret_b64")
        .ok_or_else(|| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
    if part.encoding != keystore::KeyPartEncoding::Base64 {
        return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
    }
    let bytes = utils::decode_b64_32("X25519 私钥", &part.value)?;
    Ok(X25519StaticSecret::from(*bytes))
}

/// 产品规则：X25519 必须“公钥+私钥”都齐全才允许加/解密。
fn ensure_full(entry: &keystore::KeyEntry) -> Result<(), String> {
    let has_secret = keystore::has_part(entry, "x25519_secret_b64");
    let has_public = keystore::has_part(entry, "x25519_public_b64");
    if has_secret && has_public {
        Ok(())
    } else {
        Err("X25519 加/解密需要同时包含公钥与私钥（当前条目不完整）".to_string())
    }
}

/// 规范化并校验“导入/编辑保存”提交的 parts（X25519）。
///
/// 规则（按产品约束）：
/// - 允许仅公钥 / 仅私钥 / 完整，但真正加/解密必须完整（ensure_full 会检查）。
fn normalize_parts(parts: Vec<keystore::KeyPart>) -> Result<Vec<keystore::KeyPart>, String> {
    let mut map = utils::collect_parts_unique(parts)?;

    let public_in = map.remove("x25519_public_b64");
    let secret_in = map.remove("x25519_secret_b64");

    if public_in.is_none() && secret_in.is_none() {
        return Err("X25519 至少需要填写公钥或私钥".to_string());
    }

    if !map.is_empty() {
        let extra = map.keys().cloned().collect::<Vec<_>>().join(", ");
        return Err(format!("X25519 不支持的字段：{extra}"));
    }

    // 公钥：Base64 解码后必须为 32 字节，并规范化输出为标准 Base64。
    let public_norm = if let Some(p) = public_in {
        if p.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("x25519_public_b64 的 encoding 必须为 base64".to_string());
        }
        let bytes = B64
            .decode(p.value.trim().as_bytes())
            .map_err(|e| format!("X25519 公钥 Base64 解码失败：{e}"))?;
        if bytes.len() != 32 {
            return Err("X25519 公钥必须为 32 字节（Base64 解码后）".to_string());
        }
        Some(B64.encode(bytes))
    } else {
        None
    };

    // 私钥：Base64 解码后必须为 32 字节，并规范化输出为标准 Base64。
    let secret_norm = if let Some(p) = secret_in {
        if p.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("x25519_secret_b64 的 encoding 必须为 base64".to_string());
        }
        let bytes = B64
            .decode(p.value.trim().as_bytes())
            .map_err(|e| format!("X25519 私钥 Base64 解码失败：{e}"))?;
        if bytes.len() != 32 {
            return Err("X25519 私钥必须为 32 字节（Base64 解码后）".to_string());
        }
        Some(B64.encode(bytes))
    } else {
        None
    };

    // 若两者都提供：校验公钥必须与私钥匹配（不做自动修复/推导）。
    if let (Some(secret_b64), Some(public_b64)) = (&secret_norm, &public_norm) {
        let secret_vec = B64
            .decode(secret_b64.as_bytes())
            .map_err(|e| format!("X25519 私钥 Base64 解码失败：{e}"))?;
        let secret_bytes: [u8; 32] = secret_vec
            .as_slice()
            .try_into()
            .map_err(|_| "X25519 私钥长度不正确".to_string())?;
        let derived_public = X25519PublicKey::from(&X25519StaticSecret::from(secret_bytes));
        let derived_b64 = B64.encode(derived_public.as_bytes());
        if derived_b64 != public_b64.as_str() {
            return Err("X25519 公钥与私钥不匹配".to_string());
        }
    }

    let mut out = Vec::new();
    if let Some(public_b64) = public_norm {
        out.push(keystore::KeyPart {
            id: "x25519_public_b64".to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: public_b64,
        });
    }
    if let Some(secret_b64) = secret_norm {
        out.push(keystore::KeyPart {
            id: "x25519_secret_b64".to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: secret_b64,
        });
    }

    Ok(out)
}

pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    // 业务规则：必须完整（公钥+私钥）。
    ensure_full(entry)?;

    let recipient_pub = parse_public(entry)?;
    let eph_secret = X25519StaticSecret::random_from_rng(OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_pub);

    // nonce 同时作为 AEAD nonce 与 HKDF salt（随机 12 字节即可）
    let nonce = utils::random_nonce_12();
    let hk = Hkdf::<Sha256>::new(Some(&nonce), shared.as_bytes());
    let mut derived = Zeroizing::new([0u8; 32]);
    hk.expand(b"encryption-tool:text:v1", derived.as_mut())
        .map_err(|_| "加密失败".to_string())?;

    // data_alg：数据侧固定使用 AES-256-GCM（与现有实现保持一致）。
    let data_ct = super::aes256::text_encrypt_with_session_key(&derived, &nonce, plaintext)?;

    Ok((
        TextCipherPayload::HybridX25519 {
            alg: "X25519".to_string(),
            data_alg: "AES-256".to_string(),
            nonce_b64: B64.encode(nonce),
            eph_public_b64: B64.encode(eph_public.as_bytes()),
            ciphertext_b64: B64.encode(data_ct),
        },
        true,
    ))
}

pub fn text_decrypt(
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    match payload {
        TextCipherPayload::HybridX25519 {
            alg,
            data_alg,
            nonce_b64,
            eph_public_b64,
            ciphertext_b64,
            ..
        } => {
            if alg != "X25519" || data_alg != "AES-256" {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }

            // 产品规则：必须完整（公钥+私钥）。
            ensure_full(entry).map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;

            let secret = parse_secret(entry)?;

            let eph_pub_bytes = B64
                .decode(eph_public_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            if eph_pub_bytes.len() != 32 {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }
            let eph_pub_arr: [u8; 32] = eph_pub_bytes
                .as_slice()
                .try_into()
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let eph_pub = X25519PublicKey::from(eph_pub_arr);
            let shared = secret.diffie_hellman(&eph_pub);

            let nonce = utils::decode_b64_12("nonce", &nonce_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;

            let hk = Hkdf::<Sha256>::new(Some(&nonce), shared.as_bytes());
            let mut derived = Zeroizing::new([0u8; 32]);
            hk.expand(b"encryption-tool:text:v1", derived.as_mut())
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;

            let ct = B64
                .decode(ciphertext_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            super::aes256::text_decrypt_with_session_key(&derived, &nonce, &ct)
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 由 nonce_prefix(8) + counter(u32) 构造 12 字节 nonce（与 file_crypto 的规则保持一致）。
fn make_nonce_12(prefix8: &[u8; 8], counter: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(prefix8);
    out[8..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// 文件加密：构造 HybridX25519Stream header，并派生数据侧 key。
pub fn file_encrypt_prepare(
    public_32: [u8; 32],
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, Zeroizing<[u8; 32]>), String> {
    let recipient_pub = X25519PublicKey::from(public_32);

    // 生成临时密钥对（发送方）。
    let eph_secret = X25519StaticSecret::random_from_rng(OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_pub);

    // HKDF 盐：使用“第 0 块 nonce（12字节）”，与 file_crypto 现有实现对齐。
    let nonce0 = make_nonce_12(&meta.nonce_prefix_8, 0);
    let hk = Hkdf::<Sha256>::new(Some(&nonce0), shared.as_bytes());
    let mut derived = Zeroizing::new([0u8; 32]);
    hk.expand(b"encryption-tool:file:v1", derived.as_mut())
        .map_err(|_| "HKDF 派生失败".to_string())?;

    let header = FileCipherHeader::HybridX25519Stream {
        alg: "X25519".to_string(),
        data_alg: "AES-256".to_string(),
        chunk_size: meta.chunk_size,
        file_size: meta.file_size,
        original_file_name: meta.original_file_name,
        original_extension: meta.original_extension,
        nonce_prefix_b64: meta.nonce_prefix_b64,
        eph_public_b64: B64.encode(eph_public.as_bytes()),
    };

    Ok((header, derived))
}

/// 文件解密：根据 header.eph_public_b64 + 私钥 + nonce0，派生数据侧 key。
pub fn file_decrypt_derive_data_key(
    eph_public_b64: &str,
    secret_32: &Zeroizing<[u8; 32]>,
    nonce0_12: &[u8; 12],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let eph_pub_bytes = B64
        .decode(eph_public_b64.trim())
        .map_err(|_| crate::file_crypto::DECRYPT_FAIL_MSG.to_string())?;
    if eph_pub_bytes.len() != 32 {
        return Err(crate::file_crypto::DECRYPT_FAIL_MSG.to_string());
    }
    let eph_pub_arr: [u8; 32] = eph_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| crate::file_crypto::DECRYPT_FAIL_MSG.to_string())?;
    let eph_pub = X25519PublicKey::from(eph_pub_arr);

    // Zeroizing<[u8;32]> 的解引用会得到 Zeroizing 本体（不是内部数组），
    // 这里显式拷贝到定长数组，确保满足 `StaticSecret: From<[u8; 32]>`。
    let mut sec_arr = [0u8; 32];
    sec_arr.copy_from_slice(secret_32.as_ref());
    let secret = X25519StaticSecret::from(sec_arr);
    let shared = secret.diffie_hellman(&eph_pub);

    let hk = Hkdf::<Sha256>::new(Some(nonce0_12), shared.as_bytes());
    let mut derived = Zeroizing::new([0u8; 32]);
    hk.expand(b"encryption-tool:file:v1", derived.as_mut())
        .map_err(|_| crate::file_crypto::DECRYPT_FAIL_MSG.to_string())?;

    Ok(derived)
}
