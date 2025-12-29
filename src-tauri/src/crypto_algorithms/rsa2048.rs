/*
  RSA2048 算法实现（文本 + 文件）。

  注意：
  - 运行期加解密逻辑由 rsa_common.rs 统一实现；
  - 本文件只做两件事：
    1) 声明算法 spec（SPEC）
    2) 提供“2048 位”密钥生成入口，以及把算法 id 固定为 RSA2048
*/

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::TextCipherPayload;
use zeroize::Zeroizing;

pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: "RSA2048",
    category: AlgorithmCategory::Asymmetric,
    encrypt_needs: "加密需要公钥（PEM）；解密需要私钥（PEM）；长文本/文件走混合加密",
    decrypt_needs: "解密需要私钥（PEM）",
};

/// 生成 RSA2048 密钥对（PKCS8 私钥 PEM + SPKI 公钥 PEM）。
pub fn generate_keypair_pem() -> Result<(String, String), String> {
    super::rsa_common::generate_keypair_pem(2048)
}

pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    super::rsa_common::text_encrypt("RSA2048", entry, plaintext)
}

pub fn text_decrypt(
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    super::rsa_common::text_decrypt("RSA2048", entry, payload)
}

pub fn file_encrypt_prepare(
    public_pem: String,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, Zeroizing<[u8; 32]>), String> {
    super::rsa_common::file_encrypt_prepare("RSA2048", public_pem, meta)
}

pub fn file_decrypt_unwrap_data_key(
    wrapped_key_b64: &str,
    private_pem: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    super::rsa_common::file_decrypt_unwrap_data_key(wrapped_key_b64, private_pem)
}
