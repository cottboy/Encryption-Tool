/*
  文本加密/解密核心（Rust 后端执行）：
  - 需求要求：加密/解密必须在后端执行，前端只负责 UI 与参数收集。
  - 输出格式：使用 JSON “自描述容器”，便于未来扩展与兼容。
  - 安全策略：
    1) 对称加密一律使用 AEAD（认证加密，防篡改）
    2) RSA：优先尝试 OAEP 直接加密；超出长度限制时自动切换为混合加密
    3) X25519：天然走混合加密（协商共享密钥 → 派生会话密钥 → AEAD 加密正文）
  - 错误策略：
    - 解密失败统一提示“密钥错误或数据已损坏”，避免向 UI 泄露过多细节。
*/

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::keystore;

/// 文本加密容器版本：将来结构变更可用它做兼容/迁移。
const TEXT_CIPHER_VERSION: u32 = 1;

/// 统一的“密钥错误/数据损坏”提示：解密失败必须明确提示，但不泄露细节。
const DECRYPT_FAIL_MSG: &str = "密钥错误或数据已损坏";

/// 文本加密输出：前端拿到后直接放到“输出框”。
#[derive(Debug, Serialize)]
pub struct TextEncryptResponse {
    /// 加密后的 JSON 字符串（自描述容器）。
    pub ciphertext: String,

    /// RSA 场景：是否由于明文超长而启用混合加密（UI 用于提示）。
    pub used_hybrid: bool,
}

/// 文本解密输出：前端拿到后直接放到“输出框”。
#[derive(Debug, Serialize)]
pub struct TextDecryptResponse {
    /// 解密得到的明文。
    pub plaintext: String,
}

/// 文本加密 JSON 容器：
/// - 使用 `kind` 作为 tag：便于区分不同算法/模式。
/// - 所有二进制字段统一用 Base64。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TextCipherPayload {
    /// 对称 AEAD（AES-256-GCM / ChaCha20-Poly1305）
    SymmetricAead {
        v: u32,
        alg: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },

    /// RSA-OAEP 直接加密（仅当明文较短时可用）
    RsaOaep {
        v: u32,
        alg: String,
        ciphertext_b64: String,
    },

    /// RSA 混合加密：
    /// - wrapped_key_b64：RSA-OAEP 包裹的 32 字节会话密钥
    /// - ciphertext_b64：使用 data_alg 对正文做 AEAD 后的密文（含 tag）
    HybridRsa {
        v: u32,
        alg: String,
        data_alg: String,
        nonce_b64: String,
        wrapped_key_b64: String,
        ciphertext_b64: String,
    },

    /// X25519 混合加密：
    /// - eph_public_b64：发送方临时公钥（32 字节），用于接收方复原共享密钥
    /// - ciphertext_b64：使用 data_alg 对正文做 AEAD 后的密文（含 tag）
    HybridX25519 {
        v: u32,
        alg: String,
        data_alg: String,
        nonce_b64: String,
        eph_public_b64: String,
        ciphertext_b64: String,
    },
}

/// 从密钥库中按 id 找到条目：找不到则返回错误给前端。
fn find_entry<'a>(plain: &'a keystore::KeyStorePlain, key_id: &str) -> Result<&'a keystore::KeyEntry, String> {
    plain
        .key_entries
        .iter()
        .find(|e| e.id == key_id)
        .ok_or_else(|| "未找到指定的密钥".to_string())
}

/// 解码 Base64 到固定 32 字节（对称密钥 / X25519 私钥等）。
fn decode_b64_32(label: &str, s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = B64.decode(s.trim()).map_err(|e| format!("{label} Base64 解码失败：{e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{label} 必须为 32 字节"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 生成随机 nonce（12 字节）：AEAD 推荐长度。
fn random_nonce_12() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// 使用 AEAD 加密：输入 key(32) + nonce(12) + 明文，输出密文（含 tag）。
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
        _ => Err("不支持的对称算法".to_string()),
    }
}

/// 使用 AEAD 解密：输入 key(32) + nonce(12) + 密文（含 tag），输出明文。
fn aead_decrypt(alg: &str, key_32: &[u8; 32], nonce_12: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        "AES-256" => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_32));
            cipher
                .decrypt(AesNonce::from_slice(nonce_12), ciphertext)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())
        }
        "ChaCha20" => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key_32));
            cipher
                .decrypt(ChaChaNonce::from_slice(nonce_12), ciphertext)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())
        }
        _ => Err(DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 计算 RSA-OAEP 可直接加密的最大长度（字节）。
/// - 公式：k - 2*hLen - 2
///   - k：模长（字节）
///   - hLen：哈希长度（SHA-256 为 32）
fn rsa_oaep_max_len(pub_key: &RsaPublicKey) -> usize {
    let k = pub_key.size();
    // 防御性写法：避免下溢。
    k.saturating_sub(2 * 32 + 2)
}

/// 解析 RSA 公钥（支持：
/// - 私钥 PEM：从中取公钥
/// - 公钥 PEM：直接使用）
fn parse_rsa_public(entry: &keystore::KeyEntry) -> Result<RsaPublicKey, String> {
    match &entry.material {
        keystore::KeyMaterial::RsaPrivate { public_pem, .. } => {
            RsaPublicKey::from_public_key_pem(public_pem).map_err(|e| format!("RSA 公钥解析失败：{e}"))
        }
        keystore::KeyMaterial::RsaPublic { public_pem } => {
            RsaPublicKey::from_public_key_pem(public_pem).map_err(|e| format!("RSA 公钥解析失败：{e}"))
        }
        _ => Err("密钥类型不匹配：需要 RSA".to_string()),
    }
}

/// 解析 RSA 私钥（仅支持私钥 PEM）。
fn parse_rsa_private(entry: &keystore::KeyEntry) -> Result<RsaPrivateKey, String> {
    match &entry.material {
        keystore::KeyMaterial::RsaPrivate { private_pem, .. } => {
            RsaPrivateKey::from_pkcs8_pem(private_pem).map_err(|_| DECRYPT_FAIL_MSG.to_string())
        }
        _ => Err(DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 解析 X25519 公钥（Base64 32 字节）。
fn parse_x25519_public(entry: &keystore::KeyEntry) -> Result<X25519PublicKey, String> {
    match &entry.material {
        keystore::KeyMaterial::X25519 { public_b64, .. } => {
            let bytes = decode_b64_32("X25519 公钥", public_b64)?;
            Ok(X25519PublicKey::from(*bytes))
        }
        _ => Err("密钥类型不匹配：需要 X25519".to_string()),
    }
}

/// 解析 X25519 私钥（Base64 32 字节）。
fn parse_x25519_secret(entry: &keystore::KeyEntry) -> Result<X25519StaticSecret, String> {
    match &entry.material {
        keystore::KeyMaterial::X25519 { secret_b64, .. } => {
            let bytes = decode_b64_32("X25519 私钥", secret_b64)?;
            Ok(X25519StaticSecret::from(*bytes))
        }
        _ => Err(DECRYPT_FAIL_MSG.to_string()),
    }
}

/// 解析对称密钥（Base64 32 字节）。
fn parse_symmetric_key(entry: &keystore::KeyEntry) -> Result<Zeroizing<[u8; 32]>, String> {
    match &entry.material {
        keystore::KeyMaterial::Symmetric { key_b64 } => decode_b64_32("对称密钥", key_b64),
        _ => Err("密钥类型不匹配：需要对称密钥".to_string()),
    }
}

/// 文本加密：
/// - algorithm：AES-256 / ChaCha20 / RSA / X25519
/// - key_id：密钥库条目 id
/// - input：明文（UTF-8 字符串）
pub fn encrypt_text(plain: &keystore::KeyStorePlain, algorithm: &str, key_id: &str, input: &str) -> Result<TextEncryptResponse, String> {
    let algo = algorithm.trim();
    let key_id = key_id.trim();
    if algo.is_empty() {
        return Err("请选择算法".to_string());
    }
    if key_id.is_empty() {
        return Err("请选择密钥".to_string());
    }

    // 找到密钥条目，并做“算法与密钥类型”匹配校验。
    let entry = find_entry(plain, key_id)?;
    if entry.key_type != algo {
        return Err("算法与密钥类型不匹配".to_string());
    }

    let plaintext = input.as_bytes();

    match algo {
        "AES-256" | "ChaCha20" => {
            // 对称加密：直接使用密钥库中的 32 字节密钥。
            let key_32 = parse_symmetric_key(entry)?;
            let nonce = random_nonce_12();
            let ct = aead_encrypt(algo, &key_32, &nonce, plaintext)?;

            let payload = TextCipherPayload::SymmetricAead {
                v: TEXT_CIPHER_VERSION,
                alg: algo.to_string(),
                nonce_b64: B64.encode(nonce),
                ciphertext_b64: B64.encode(ct),
            };

            Ok(TextEncryptResponse {
                ciphertext: serde_json::to_string(&payload).map_err(|e| format!("序列化失败：{e}"))?,
                used_hybrid: false,
            })
        }
        "RSA" => {
            // RSA：优先尝试 OAEP 直接加密；超长时自动切换为混合加密。
            let pub_key = parse_rsa_public(entry)?;
            let padding = Oaep::new::<Sha256>();
            let max_len = rsa_oaep_max_len(&pub_key);

            if plaintext.len() <= max_len {
                // 直接 RSA-OAEP：仅适用于很短的文本（字节级限制）。
                let ct = pub_key
                    .encrypt(&mut OsRng, padding, plaintext)
                    .map_err(|_| "加密失败".to_string())?;

                let payload = TextCipherPayload::RsaOaep {
                    v: TEXT_CIPHER_VERSION,
                    alg: "RSA".to_string(),
                    ciphertext_b64: B64.encode(ct),
                };

                Ok(TextEncryptResponse {
                    ciphertext: serde_json::to_string(&payload).map_err(|e| format!("序列化失败：{e}"))?,
                    used_hybrid: false,
                })
            } else {
                // 混合加密：随机会话密钥 + AEAD 加密正文；RSA-OAEP 仅包裹会话密钥。
                let mut session_key = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(session_key.as_mut());

                // data_alg：混合加密的“数据加密”部分固定使用 AES-256（AEAD：AES-256-GCM）。
                // - 需求确认：希望混合加密统一用 AES-256，而不是 ChaCha20。
                // - 注意：nonce 仍然是每次随机生成的 12 字节（GCM 推荐长度）。
                let data_alg = "AES-256";
                let nonce = random_nonce_12();
                let data_ct = aead_encrypt(data_alg, &session_key, &nonce, plaintext)?;

                let wrapped = pub_key
                    .encrypt(&mut OsRng, Oaep::new::<Sha256>(), session_key.as_ref())
                    .map_err(|_| "加密失败".to_string())?;

                let payload = TextCipherPayload::HybridRsa {
                    v: TEXT_CIPHER_VERSION,
                    alg: "RSA".to_string(),
                    data_alg: data_alg.to_string(),
                    nonce_b64: B64.encode(nonce),
                    wrapped_key_b64: B64.encode(wrapped),
                    ciphertext_b64: B64.encode(data_ct),
                };

                Ok(TextEncryptResponse {
                    ciphertext: serde_json::to_string(&payload).map_err(|e| format!("序列化失败：{e}"))?,
                    used_hybrid: true,
                })
            }
        }
        "X25519" => {
            // X25519：天然混合加密
            // - 生成临时密钥对（发送方）
            // - 与接收方公钥做 DH 得到共享密钥
            // - 用 HKDF 派生 32 字节会话密钥，再用 AEAD 加密正文
            let recipient_pub = parse_x25519_public(entry)?;

            // 临时私钥（32 字节随机）+ 临时公钥（随 payload 输出）
            let mut eph_bytes = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(eph_bytes.as_mut());
            let eph_secret = X25519StaticSecret::from(*eph_bytes);
            let eph_public = X25519PublicKey::from(&eph_secret);

            // 共享密钥：32 字节
            let shared = eph_secret.diffie_hellman(&recipient_pub);

            // nonce 同时作为 AEAD nonce 与 HKDF salt（随机 12 字节即可）
            let nonce = random_nonce_12();
            let hk = Hkdf::<Sha256>::new(Some(&nonce), shared.as_bytes());
            let mut derived = Zeroizing::new([0u8; 32]);
            hk.expand(b"encryption-tool:text:v1", derived.as_mut())
                .map_err(|_| "加密失败".to_string())?;

            // data_alg：混合加密的“数据加密”部分固定使用 AES-256（AEAD：AES-256-GCM）。
            // - 需求确认：希望 X25519 协商出的会话密钥用于 AES-256-GCM。
            let data_alg = "AES-256";
            let data_ct = aead_encrypt(data_alg, &derived, &nonce, plaintext)?;

            let payload = TextCipherPayload::HybridX25519 {
                v: TEXT_CIPHER_VERSION,
                alg: "X25519".to_string(),
                data_alg: data_alg.to_string(),
                nonce_b64: B64.encode(nonce),
                eph_public_b64: B64.encode(eph_public.as_bytes()),
                ciphertext_b64: B64.encode(data_ct),
            };

            Ok(TextEncryptResponse {
                ciphertext: serde_json::to_string(&payload).map_err(|e| format!("序列化失败：{e}"))?,
                used_hybrid: true,
            })
        }
        _ => Err("不支持的算法".to_string()),
    }
}

/// 文本解密：
/// - algorithm：AES-256 / ChaCha20 / RSA / X25519（用于匹配校验）
/// - key_id：密钥库条目 id
/// - input：密文 JSON 字符串
pub fn decrypt_text(plain: &keystore::KeyStorePlain, algorithm: &str, key_id: &str, input: &str) -> Result<TextDecryptResponse, String> {
    let algo = algorithm.trim();
    let key_id = key_id.trim();
    if algo.is_empty() || key_id.is_empty() {
        return Err(DECRYPT_FAIL_MSG.to_string());
}

    // 先加载密钥，并做基础匹配（注意：解密错误不应泄露细节）。
    let entry = find_entry(plain, key_id).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
    if entry.key_type != algo {
        return Err(DECRYPT_FAIL_MSG.to_string());
    }

    // 解析密文容器（解析失败视为“数据损坏”）。
    let payload: TextCipherPayload = serde_json::from_str(input.trim()).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

    // 版本检查：将来版本升级可在此做兼容。
    // 当前策略：版本不一致直接视为无法解密。
    let version_ok = match &payload {
        TextCipherPayload::SymmetricAead { v, .. }
        | TextCipherPayload::RsaOaep { v, .. }
        | TextCipherPayload::HybridRsa { v, .. }
        | TextCipherPayload::HybridX25519 { v, .. } => *v == TEXT_CIPHER_VERSION,
    };
    if !version_ok {
        return Err(DECRYPT_FAIL_MSG.to_string());
    }

    match payload {
        TextCipherPayload::SymmetricAead {
            alg,
            nonce_b64,
            ciphertext_b64,
            ..
        } => {
            if alg != algo {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let key_32 = parse_symmetric_key(entry).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let nonce_bytes = B64.decode(nonce_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if nonce_bytes.len() != 12 {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let ct = B64.decode(ciphertext_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let pt = aead_decrypt(&alg, &key_32, &nonce, &ct)?;
            let out = String::from_utf8(pt).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            Ok(TextDecryptResponse { plaintext: out })
        }
        TextCipherPayload::RsaOaep { alg, ciphertext_b64, .. } => {
            if alg != "RSA" || algo != "RSA" {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let priv_key = parse_rsa_private(entry)?;
            let ct = B64.decode(ciphertext_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let pt = priv_key
                .decrypt(Oaep::new::<Sha256>(), &ct)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let out = String::from_utf8(pt).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            Ok(TextDecryptResponse { plaintext: out })
        }
        TextCipherPayload::HybridRsa {
            alg,
            data_alg,
            nonce_b64,
            wrapped_key_b64,
            ciphertext_b64,
            ..
        } => {
            if alg != "RSA" || algo != "RSA" {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let priv_key = parse_rsa_private(entry)?;
            let wrapped = B64.decode(wrapped_key_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let session = priv_key
                .decrypt(Oaep::new::<Sha256>(), &wrapped)
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if session.len() != 32 {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let mut session_key = Zeroizing::new([0u8; 32]);
            session_key.copy_from_slice(&session);

            let nonce_bytes = B64.decode(nonce_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if nonce_bytes.len() != 12 {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let ct = B64.decode(ciphertext_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let pt = aead_decrypt(&data_alg, &session_key, &nonce, &ct)?;
            let out = String::from_utf8(pt).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            Ok(TextDecryptResponse { plaintext: out })
        }
        TextCipherPayload::HybridX25519 {
            alg,
            data_alg,
            nonce_b64,
            eph_public_b64,
            ciphertext_b64,
            ..
        } => {
            if alg != "X25519" || algo != "X25519" {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }

            let secret = parse_x25519_secret(entry)?;

            let eph_pub_bytes = B64.decode(eph_public_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if eph_pub_bytes.len() != 32 {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let eph_pub_arr: [u8; 32] = eph_pub_bytes.as_slice().try_into().map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let eph_pub = X25519PublicKey::from(eph_pub_arr);
            let shared = secret.diffie_hellman(&eph_pub);

            let nonce_bytes = B64.decode(nonce_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            if nonce_bytes.len() != 12 {
                return Err(DECRYPT_FAIL_MSG.to_string());
            }
            let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

            let hk = Hkdf::<Sha256>::new(Some(&nonce), shared.as_bytes());
            let mut derived = Zeroizing::new([0u8; 32]);
            hk.expand(b"encryption-tool:text:v1", derived.as_mut())
                .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

            let ct = B64.decode(ciphertext_b64).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            let pt = aead_decrypt(&data_alg, &derived, &nonce, &ct)?;
            let out = String::from_utf8(pt).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
            Ok(TextDecryptResponse { plaintext: out })
        }
    }
}
