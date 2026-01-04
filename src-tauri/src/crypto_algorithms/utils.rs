/*
  crypto_algorithms 公共工具：
  - 这些函数用于多个算法实现，避免在各算法文件里重复写 Base64 解码、随机 nonce 等样板代码。
  - 注意：这里不做“业务分发”，只做纯工具。
*/

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::keystore;

/// 解密失败统一提示（文本/文件解密都要尽量收敛错误信息）。
///
/// 说明：
/// - text_crypto 与 file_crypto 都各自有一份常量；
/// - 这里的工具函数无法区分上下文，因此只在“参数校验”层面复用；
/// - 具体错误收敛仍由调用方负责。
pub const GENERIC_DECRYPT_FAIL_MSG: &str = "密钥错误或数据已损坏";

/// 生成 12 字节随机 nonce（适用于 AES-GCM / ChaCha20-Poly1305）。
pub fn random_nonce_12() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Base64 解码并校验长度为 32 字节，返回 Zeroizing 包裹的数组。
pub fn decode_b64_32(name: &str, b64: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|e| format!("{name} Base64 解码失败：{e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name} 长度必须为 32 字节（Base64 解码后）"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Base64 解码并校验长度为 12 字节（nonce）。
pub fn decode_b64_12(name: &str, b64: &str) -> Result<[u8; 12], String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|_| GENERIC_DECRYPT_FAIL_MSG.to_string())?;
    if bytes.len() != 12 {
        return Err(format!("{name} 长度不正确"));
    }
    let mut out = [0u8; 12];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Base64 解码并校验长度为 8 字节（nonce_prefix）。
#[allow(dead_code)]
pub fn decode_b64_8(name: &str, b64: &str) -> Result<[u8; 8], String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|_| GENERIC_DECRYPT_FAIL_MSG.to_string())?;
    if bytes.len() != 8 {
        return Err(format!("{name} 长度不正确"));
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 将 parts 列表整理成“唯一 id → part”的 Map，并做最基础的清洗。
///
/// 这一步做的事情：
/// - 去掉 id/value 的首尾空白（避免用户复制粘贴时带多余空格导致“看似相同但实际不同”）；
/// - 校验 id 不能为空；
/// - 校验同一个 id 不能出现多次（避免前端/用户误操作导致覆盖逻辑不明确）。
///
/// 为什么用 BTreeMap：
/// - 让输出错误信息/调试打印稳定；
/// - 落盘 parts 的顺序也更稳定（便于 diff 与排查）。
pub fn collect_parts_unique(
    parts: Vec<keystore::KeyPart>,
) -> Result<BTreeMap<String, keystore::KeyPart>, String> {
    let mut map: BTreeMap<String, keystore::KeyPart> = BTreeMap::new();

    for mut p in parts {
        let id = p.id.trim();
        if id.is_empty() {
            return Err("part.id 不能为空".to_string());
        }
        p.id = id.to_string();
        p.value = p.value.trim().to_string();

        if map.contains_key(&p.id) {
            return Err(format!("重复的 part id：{}", p.id));
        }

        // 注意：value 允许为空（表示用户清空/未填写）；具体是否允许由算法模块决定。
        map.insert(p.id.clone(), p);
    }

    Ok(map)
}
