/*
  crypto_algorithms 公共工具：
  - 这些函数用于多个算法实现，避免在各算法文件里重复写 Base64 解码、随机 nonce 等样板代码。
  - 注意：这里不做“业务分发”，只做纯工具。
*/

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

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
