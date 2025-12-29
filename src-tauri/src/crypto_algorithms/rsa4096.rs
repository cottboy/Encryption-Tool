/*
  RSA4096 算法实现（文本 + 文件）。

  与 rsa2048.rs 同理：
  - 加解密逻辑复用 rsa_common.rs
  - 只把“算法 id 固定为 RSA4096”以及“生成 4096 位密钥对”留在本文件
*/

use crate::crypto_algorithms::{AlgorithmCategory, AlgorithmSpec, FileEncryptMeta};
use crate::file_crypto::FileCipherHeader;
use crate::keystore;
use crate::text_crypto::TextCipherPayload;
use zeroize::Zeroizing;

pub(super) const SPEC: AlgorithmSpec = AlgorithmSpec {
    id: "RSA4096",
    category: AlgorithmCategory::Asymmetric,
    encrypt_needs: "加密需要公钥（PEM）；解密需要私钥（PEM）；长文本/文件走混合加密",
    decrypt_needs: "解密需要私钥（PEM）",
};

/// 生成 RSA4096 密钥对（PKCS8 私钥 PEM + SPKI 公钥 PEM）。
pub fn generate_keypair_pem() -> Result<(String, String), String> {
    super::rsa_common::generate_keypair_pem(4096)
}

pub fn text_encrypt(
    entry: &keystore::KeyEntry,
    plaintext: &[u8],
) -> Result<(TextCipherPayload, bool), String> {
    super::rsa_common::text_encrypt("RSA4096", entry, plaintext)
}

pub fn text_decrypt(
    entry: &keystore::KeyEntry,
    payload: TextCipherPayload,
) -> Result<Vec<u8>, String> {
    super::rsa_common::text_decrypt("RSA4096", entry, payload)
}

pub fn file_encrypt_prepare(
    public_pem: String,
    meta: FileEncryptMeta,
) -> Result<(FileCipherHeader, Zeroizing<[u8; 32]>), String> {
    super::rsa_common::file_encrypt_prepare("RSA4096", public_pem, meta)
}

pub fn file_decrypt_unwrap_data_key(
    wrapped_key_b64: &str,
    private_pem: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    super::rsa_common::file_decrypt_unwrap_data_key(wrapped_key_b64, private_pem)
}
