/*
  ML-KEM-768（后量子 KEM）算法实现：

  产品规则（已确认）：
  - 只做“一次封装建立会话”：
    - B 使用 A 的公钥封装：得到 (ct, ss)，把 ct 发送给 A，同时将 ss 写入 keystore.json（不在前端展示）
    - A 使用自己的私钥 + ct 解封：得到同一个 ss，并写入 keystore.json
  - 后续文本/文件加解密：只要 keystore 中存在 ss，就允许加/解密；数据侧统一使用 AES-256-GCM。

  UI 字段（按你的要求顺序）：
  - 公钥
  - 私钥
  - 封装密钥（实际是封装密文 ct）
*/

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use zeroize::Zeroizing;

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta, KeyPartSpec};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::TextCipherPayload;

use super::utils;

const ALG_ID: &str = "ML-KEM-768";
const DATA_ALG: &str = "AES-256";

const PART_PUBLIC: &str = "mlkem768_public_b64";
const PART_SECRET: &str = "mlkem768_secret_b64";
const PART_CT: &str = "mlkem768_ct_b64";
const PART_SHARED: &str = "mlkem768_shared_b64";

pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: ALG_ID,
    category: AlgorithmCategory::Asymmetric,
    encrypt_needs_key: "algorithms.needs.ML-KEM-768.encrypt",
    decrypt_needs_key: "algorithms.needs.ML-KEM-768.decrypt",
    key_parts: &[
        KeyPartSpec {
            id: PART_PUBLIC,
            encoding: keystore::KeyPartEncoding::Base64,
            hidden: false,
            label_key: "keys.ui.preview.publicB64",
            placeholder_key: Some("keys.ui.placeholders.mlkem768PublicB64"),
            rows: 4,
            hint_key: None,
            required_for_encrypt: false,
            required_for_decrypt: false,
        },
        KeyPartSpec {
            id: PART_SECRET,
            encoding: keystore::KeyPartEncoding::Base64,
            hidden: false,
            label_key: "keys.ui.preview.secretB64",
            placeholder_key: Some("keys.ui.placeholders.mlkem768SecretB64"),
            rows: 4,
            hint_key: None,
            required_for_encrypt: false,
            required_for_decrypt: false,
        },
        KeyPartSpec {
            id: PART_CT,
            encoding: keystore::KeyPartEncoding::Base64,
            hidden: false,
            label_key: "keys.ui.preview.mlkem768CiphertextB64",
            placeholder_key: Some("keys.ui.placeholders.mlkem768CtB64"),
            rows: 4,
            hint_key: None,
            required_for_encrypt: false,
            required_for_decrypt: false,
        },
        // 共享密钥：不在前端展示，但决定是否允许加/解密。
        KeyPartSpec {
            id: PART_SHARED,
            encoding: keystore::KeyPartEncoding::Base64,
            hidden: true,
            label_key: "keys.ui.preview.mlkem768SharedB64",
            placeholder_key: None,
            rows: 4,
            hint_key: None,
            required_for_encrypt: true,
            required_for_decrypt: true,
        },
    ],
    normalize_parts,
};

pub fn generate_keypair_b64() -> (String, String) {
    let (pk, sk) = mlkem768::keypair();
    (B64.encode(sk.as_bytes()), B64.encode(pk.as_bytes()))
}

pub fn encapsulate_to_public_b64(
    public_b64: &str,
) -> Result<(String, Zeroizing<[u8; 32]>), String> {
    let pk = parse_public_b64(public_b64)?;
    let (ss, ct) = mlkem768::encapsulate(&pk);

    let mut ss_32 = Zeroizing::new([0u8; 32]);
    if ss.as_bytes().len() != 32 {
        return Err("ML-KEM-768 共享密钥长度异常".to_string());
    }
    ss_32.copy_from_slice(ss.as_bytes());

    Ok((B64.encode(ct.as_bytes()), ss_32))
}

fn parse_public_b64(public_b64: &str) -> Result<mlkem768::PublicKey, String> {
    let bytes = B64
        .decode(public_b64.trim())
        .map_err(|e| format!("ML-KEM 公钥 Base64 解码失败：{e}"))?;
    mlkem768::PublicKey::from_bytes(&bytes).map_err(|_| "ML-KEM 公钥长度不正确".to_string())
}

fn parse_secret(entry: &keystore::KeyEntry) -> Result<mlkem768::SecretKey, String> {
    let part = keystore::find_part(entry, PART_SECRET)
        .ok_or_else(|| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
    if part.encoding != keystore::KeyPartEncoding::Base64 {
        return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
    }
    let bytes = B64
        .decode(part.value.trim())
        .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
    mlkem768::SecretKey::from_bytes(&bytes)
        .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())
}

fn parse_ct_b64(ct_b64: &str) -> Result<mlkem768::Ciphertext, String> {
    let bytes = B64
        .decode(ct_b64.trim())
        .map_err(|e| format!("封装密钥 Base64 解码失败：{e}"))?;
    mlkem768::Ciphertext::from_bytes(&bytes).map_err(|_| "封装密钥长度不正确".to_string())
}

fn parse_shared(entry: &keystore::KeyEntry) -> Result<Zeroizing<[u8; 32]>, String> {
    let part = keystore::find_part(entry, PART_SHARED)
        .ok_or_else(|| "尚未建立会话：请先生成/导入封装密钥并保存".to_string())?;
    if part.encoding != keystore::KeyPartEncoding::Base64 {
        return Err("mlkem768_shared_b64 的 encoding 必须为 base64".to_string());
    }
    utils::decode_b64_32("共享密钥", &part.value)
}

pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    let ss = parse_shared(entry)?;
    let nonce = utils::random_nonce_12();
    let ct = super::aes256::text_encrypt_with_session_key(&ss, &nonce, plaintext)?;

    Ok((
        TextCipherPayload::SessionAead {
            alg: ALG_ID.to_string(),
            data_alg: DATA_ALG.to_string(),
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
        TextCipherPayload::SessionAead {
            alg,
            data_alg,
            nonce_b64,
            ciphertext_b64,
        } => {
            if alg != ALG_ID || data_alg != DATA_ALG {
                return Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string());
            }

            let ss = parse_shared(entry)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let nonce = utils::decode_b64_12("nonce", &nonce_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;
            let ct = B64
                .decode(ciphertext_b64)
                .map_err(|_| crate::text_crypto::DECRYPT_FAIL_MSG.to_string())?;

            super::aes256::text_decrypt_with_session_key(&ss, &nonce, &ct)
        }
        _ => Err(crate::text_crypto::DECRYPT_FAIL_MSG.to_string()),
    }
}

pub fn file_encrypt_prepare(
    key_32: Zeroizing<[u8; 32]>,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, Zeroizing<[u8; 32]>), String> {
    let header = FileCipherHeader::SessionStream {
        alg: ALG_ID.to_string(),
        data_alg: DATA_ALG.to_string(),
        chunk_size: meta.chunk_size,
        file_size: meta.file_size,
        original_file_name: meta.original_file_name,
        original_extension: meta.original_extension,
        nonce_prefix_b64: meta.nonce_prefix_b64,
    };
    Ok((header, key_32))
}

fn normalize_parts(parts: Vec<keystore::KeyPart>) -> Result<Vec<keystore::KeyPart>, String> {
    let mut map = utils::collect_parts_unique(parts)?;

    let public_in = map.remove(PART_PUBLIC);
    let secret_in = map.remove(PART_SECRET);
    let ct_in = map.remove(PART_CT);
    let shared_in = map.remove(PART_SHARED);

    if !map.is_empty() {
        let extra = map.keys().cloned().collect::<Vec<_>>().join(", ");
        return Err(format!("{ALG_ID} 不支持的字段：{extra}"));
    }

    // 产品一致性：导入/编辑保存时，至少填写一个字段，避免空条目污染密钥库。
    if public_in.is_none() && secret_in.is_none() && ct_in.is_none() && shared_in.is_none() {
        return Err("请至少填写一个字段".to_string());
    }

    let mut out: Vec<keystore::KeyPart> = Vec::new();

    if let Some(p) = public_in {
        if p.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("mlkem768_public_b64 的 encoding 必须为 base64".to_string());
        }
        let pk = parse_public_b64(&p.value)?;
        out.push(keystore::KeyPart {
            id: PART_PUBLIC.to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: B64.encode(pk.as_bytes()),
        });
    }

    if let Some(p) = secret_in {
        if p.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("mlkem768_secret_b64 的 encoding 必须为 base64".to_string());
        }
        let bytes = B64
            .decode(p.value.trim())
            .map_err(|e| format!("ML-KEM 私钥 Base64 解码失败：{e}"))?;
        let sk = mlkem768::SecretKey::from_bytes(&bytes)
            .map_err(|_| "ML-KEM 私钥长度不正确".to_string())?;
        out.push(keystore::KeyPart {
            id: PART_SECRET.to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: B64.encode(sk.as_bytes()),
        });
    }

    let mut normalized_ct: Option<String> = None;
    if let Some(p) = ct_in {
        if p.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("mlkem768_ct_b64 的 encoding 必须为 base64".to_string());
        }
        let ct = parse_ct_b64(&p.value)?;
        let ct_b64 = B64.encode(ct.as_bytes());
        normalized_ct = Some(ct_b64.clone());
        out.push(keystore::KeyPart {
            id: PART_CT.to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: ct_b64,
        });
    }

    if let Some(p) = shared_in {
        if p.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("mlkem768_shared_b64 的 encoding 必须为 base64".to_string());
        }
        // 共享密钥固定 32 字节：校验并标准化为规范 Base64。
        let ss = utils::decode_b64_32("共享密钥", &p.value)?;
        out.push(keystore::KeyPart {
            id: PART_SHARED.to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: B64.encode(ss.as_ref()),
        });
        return Ok(out);
    }

    // 规则：如果用户同时提交了“私钥 + 封装密钥(ct)”，则在保存时自动解封并写入共享密钥。
    if normalized_ct.is_some() && out.iter().any(|p| p.id == PART_SECRET) {
        let entry_for_decap = keystore::KeyEntry {
            id: "tmp".to_string(),
            label: "tmp".to_string(),
            key_type: ALG_ID.to_string(),
            parts: out.clone(),
        };

        let sk = parse_secret(&entry_for_decap)?;
        let ct_part = out
            .iter()
            .find(|p| p.id == PART_CT)
            .ok_or_else(|| "封装密钥缺失".to_string())?;
        let ct = parse_ct_b64(&ct_part.value)?;

        let ss = mlkem768::decapsulate(&ct, &sk);
        if ss.as_bytes().len() != 32 {
            return Err("ML-KEM-768 共享密钥长度异常".to_string());
        }

        out.push(keystore::KeyPart {
            id: PART_SHARED.to_string(),
            encoding: keystore::KeyPartEncoding::Base64,
            value: B64.encode(ss.as_bytes()),
        });
    }

    Ok(out)
}
