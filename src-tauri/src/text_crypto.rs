/*
  文本加密/解密核心（Rust 后端执行）：
  - 需求要求：加密/解密必须在后端执行，前端只负责 UI 与参数收集。
  - 输出格式：使用 JSON “自描述容器”，便于区分不同算法/模式。
  - 安全策略：
    1) 对称加密一律使用 AEAD（认证加密，防篡改）
    2) RSA（RSA-2048 / RSA-4096）：优先尝试 OAEP 直接加密；超出长度限制时自动切换为混合加密
    3) X25519：天然走混合加密（协商共享密钥 → 派生会话密钥 → AEAD 加密正文）
  - 错误策略：
    - 解密失败统一提示“密钥错误或数据已损坏”，避免向 UI 泄露过多细节。
*/

use serde::{Deserialize, Serialize};

use crate::keystore;

/// 统一的“密钥错误/数据损坏”提示：解密失败必须明确提示，但不泄露细节。
pub(crate) const DECRYPT_FAIL_MSG: &str = "密钥错误或数据已损坏";

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
pub(crate) enum TextCipherPayload {
    /// 对称 AEAD（AES-256-GCM / ChaCha20-Poly1305）
    SymmetricAead {
        alg: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },

    /// RSA-OAEP 直接加密（仅当明文较短时可用）
    RsaOaep { alg: String, ciphertext_b64: String },

    /// RSA 混合加密：
    /// - wrapped_key_b64：RSA-OAEP 包裹的 32 字节会话密钥
    /// - ciphertext_b64：使用 data_alg 对正文做 AEAD 后的密文（含 tag）
    HybridRsa {
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
        alg: String,
        data_alg: String,
        nonce_b64: String,
        eph_public_b64: String,
        ciphertext_b64: String,
    },

    /// 会话密钥 + AEAD（当前用于 ML-KEM-768 一次封装建立会话后复用会话密钥）。
    SessionAead {
        alg: String,
        data_alg: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },
}

/// 从密钥库中按 id 找到条目：找不到则返回错误给前端。
fn find_entry<'a>(
    plain: &'a keystore::KeyStorePlain,
    key_id: &str,
) -> Result<&'a keystore::KeyEntry, String> {
    plain
        .key_entries
        .iter()
        .find(|e| e.id == key_id)
        .ok_or_else(|| "未找到指定的密钥".to_string())
}

/// 文本加密：
/// - algorithm：AES-256 / ChaCha20 / RSA-2048 / RSA-4096 / X25519
/// - key_id：密钥库条目 id
/// - input：明文（UTF-8 字符串）
pub fn encrypt_text(
    plain: &keystore::KeyStorePlain,
    algorithm: &str,
    key_id: &str,
    input: &str,
) -> Result<TextEncryptResponse, String> {
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

    // 算法分发：交给 crypto_algorithms（每种算法一个文件）负责。
    let (payload, used_hybrid) = crate::crypto_algorithms::text_encrypt(algo, entry, plaintext)?;

    Ok(TextEncryptResponse {
        ciphertext: serde_json::to_string(&payload).map_err(|e| format!("序列化失败：{e}"))?,
        used_hybrid,
    })
}

/// 文本解密：
/// - algorithm：AES-256 / ChaCha20 / RSA-2048 / RSA-4096 / X25519（用于匹配校验）
/// - key_id：密钥库条目 id
/// - input：密文 JSON 字符串
pub fn decrypt_text(
    plain: &keystore::KeyStorePlain,
    algorithm: &str,
    key_id: &str,
    input: &str,
) -> Result<TextDecryptResponse, String> {
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
    let payload: TextCipherPayload =
        serde_json::from_str(input.trim()).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;

    // 具体解密逻辑交给 crypto_algorithms；此处做统一错误收敛。
    let pt = crate::crypto_algorithms::text_decrypt(algo, entry, payload)
        .map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
    let out = String::from_utf8(pt).map_err(|_| DECRYPT_FAIL_MSG.to_string())?;
    Ok(TextDecryptResponse { plaintext: out })
}
