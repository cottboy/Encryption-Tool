/*
  密钥库（KeyStore）：
  - 需求要求（已确认）：
    1) 单一密钥库：应用只管理“一个密钥库文件”。
    2) 密钥管理页进入后直接列出密钥，提供生成/导入/导出/删除等操作。
    3) 允许用户启用“密钥库加密（应用锁）”：下次打开软件必须输入密码才能使用。

  文件与格式：
  - 存储路径：AppData/keystore.json
  - JSON 容器：
    - 明文：{ format: "plain", data: {...} }
    - 加密：{ format: "encrypted", kdf: {...}, aead: {...}, ciphertext_b64: "..." }

  加密方案：
  - KDF：Argon2id
  - AEAD：AES-256-GCM（认证加密，防篡改）

  重要实现细节（写回加密库）：
  - 解锁后，我们不会保存用户明文密码。
  - 但为了“新增/删除密钥后仍能写回加密文件”，需要缓存派生后的 32 字节密钥。
  - 写回时复用原 salt/参数（nonce 每次重新生成）。
*/

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// 密钥库版本：结构变更时用于迁移。
const KEYSTORE_VERSION: u32 = 1;

/// 密钥库文件名（固定单文件）。
const KEYSTORE_FILENAME: &str = "keystore.json";

/// KDF 默认参数：不做“强度提示/锁定”，但仍然给一个相对安全的默认值。
/// - memory_kib：64 MiB
/// - time_cost：3
/// - parallelism：1
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ARGON2_TIME_COST: u32 = 3;
const DEFAULT_ARGON2_PARALLELISM: u32 = 1;

/// 密钥库内部数据（明文部分）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStorePlain {
    /// 结构版本。
    pub version: u32,

    /// 密钥条目列表。
    pub key_entries: Vec<KeyEntry>,
}

/// 密钥材料：
/// - 统一放在密钥库里，后续文本/文件加解密只需要通过 id 找到对应材料即可。
/// - 注意：这里保存的是“密钥材料本身”（密钥库若启用应用锁，会整体加密落盘）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyMaterial {
    /// 对称密钥（AES-256 / ChaCha20）：32 字节。
    Symmetric { key_b64: String },

    /// RSA 私钥（PKCS8 PEM）。
    ///
    /// 说明：
    /// - 为了支持“仅导入私钥”的场景，这里把 `public_pem` 设计为可选字段。
    /// - 如果 `public_pem` 缺失，则在 UI/业务规则上视为“仅私钥”，只允许解密，不允许加密。
    /// - 如果 `public_pem` 存在，则视为“完整”，允许加密+解密。
    RsaPrivate {
        private_pem: String,
        public_pem: Option<String>,
    },

    /// RSA 仅公钥（SPKI PEM）。
    RsaPublic { public_pem: String },

    /// X25519 密钥材料：
    ///
    /// 说明：
    /// - 需求变更：允许用户“只导入公钥”或“只导入私钥”。
    /// - 由于产品规则要求：X25519 必须同时拥有公钥+私钥才允许加/解密，因此这两个字段都设计为可选。
    /// - `secret_b64` / `public_b64` 的字节长度均要求为 32（Base64 解码后）。
    X25519 {
        secret_b64: Option<String>,
        public_b64: Option<String>,
    },
}

/// 单个密钥条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// 条目 ID：用于 UI 选择与后端定位。
    pub id: String,

    /// 用户可读名称。
    pub label: String,

    /// 密钥类型（例如 AES-256 / ChaCha20 / RSA2048 / RSA4096 / X25519）。
    pub key_type: String,

    /// 密钥材料。
    pub material: KeyMaterial,
}

/// 密钥库文件（磁盘上的 JSON 容器）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum KeyStoreFile {
    Plain {
        version: u32,
        data: KeyStorePlain,
    },
    Encrypted {
        version: u32,
        kdf: KdfParams,
        aead: AeadParams,
        ciphertext_b64: String,
    },
}

/// KDF 参数（当前使用 Argon2id）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt_b64: String,
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

/// AEAD 参数（当前使用 AES-256-GCM）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadParams {
    pub algorithm: String,
    pub nonce_b64: String,
}

/// 给前端展示的密钥库状态（不包含敏感材料）。
#[derive(Debug, Clone, Serialize)]
pub struct KeyStoreStatus {
    pub exists: bool,
    pub encrypted: bool,
    pub unlocked: bool,
    pub version: u32,
    pub key_count: Option<usize>,
}

/// KeyStore 相关错误：统一转成字符串返回给前端。
#[derive(Debug)]
pub enum KeyStoreError {
    NotFound,
    PasswordRequired,
    PasswordOrDataInvalid,
    Io(std::io::Error),
    Json(serde_json::Error),
    Crypto(String),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStoreError::NotFound => write!(f, "密钥库不存在"),
            KeyStoreError::PasswordRequired => write!(f, "应用已锁定：需要输入密码解锁"),
            KeyStoreError::PasswordOrDataInvalid => write!(f, "密码错误或密钥库已损坏"),
            KeyStoreError::Io(e) => write!(f, "文件读写错误：{e}"),
            KeyStoreError::Json(e) => write!(f, "JSON 解析错误：{e}"),
            KeyStoreError::Crypto(e) => write!(f, "加密/解密错误：{e}"),
        }
    }
}

impl From<std::io::Error> for KeyStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// 获取密钥库文件路径（AppData）。
pub fn keystore_path(app: &AppHandle) -> Result<PathBuf, KeyStoreError> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|e| KeyStoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(base.join(KEYSTORE_FILENAME))
}

/// 确保密钥库存在：不存在则创建一个明文空密钥库。
pub fn ensure_exists(app: &AppHandle) -> Result<(), KeyStoreError> {
    let path = keystore_path(app)?;
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let plain = KeyStorePlain {
        version: KEYSTORE_VERSION,
        key_entries: Vec::new(),
    };

    let file = KeyStoreFile::Plain {
        version: KEYSTORE_VERSION,
        data: plain,
    };

    write_json_atomic(&path, &file)?;
    Ok(())
}

/// 读取密钥库文件（不解密）。
pub fn read_file(app: &AppHandle) -> Result<KeyStoreFile, KeyStoreError> {
    let path = keystore_path(app)?;
    if !path.exists() {
        return Err(KeyStoreError::NotFound);
    }

    let bytes = fs::read(path)?;
    let file: KeyStoreFile = serde_json::from_slice(&bytes)?;
    Ok(file)
}

/// 获取密钥库状态。
pub fn status(app: &AppHandle, unlocked: bool) -> Result<KeyStoreStatus, KeyStoreError> {
    let path = keystore_path(app)?;
    if !path.exists() {
        return Ok(KeyStoreStatus {
            exists: false,
            encrypted: false,
            unlocked: true,
            version: KEYSTORE_VERSION,
            key_count: Some(0),
        });
    }

    let file = read_file(app)?;

    match file {
        KeyStoreFile::Plain { version, data } => Ok(KeyStoreStatus {
            exists: true,
            encrypted: false,
            unlocked: true,
            version,
            key_count: Some(data.key_entries.len()),
        }),
        KeyStoreFile::Encrypted { version, .. } => Ok(KeyStoreStatus {
            exists: true,
            encrypted: true,
            unlocked,
            version,
            key_count: None,
        }),
    }
}

/// 解密密钥库（并返回“派生密钥 + KDF 参数”，用于会话内写回）。
///
/// - 明文库：不会返回派生密钥（None）
/// - 加密库：会返回派生密钥与 KDF 参数
pub fn decrypt_with_password_and_derived_key(
    app: &AppHandle,
    password: &str,
) -> Result<(KeyStorePlain, Option<(KdfParams, [u8; 32])>), KeyStoreError> {
    let file = read_file(app)?;
    match file {
        KeyStoreFile::Plain { data, .. } => Ok((data, None)),
        KeyStoreFile::Encrypted {
            kdf,
            aead,
            ciphertext_b64,
            ..
        } => {
            let (plain, derived_key) =
                decrypt_keystore_return_key(&kdf, &aead, &ciphertext_b64, password)?;
            Ok((plain, Some((kdf, derived_key))))
        }
    }
}

/// 用“派生密钥”把明文密钥库重新加密成 `KeyStoreFile::Encrypted`。
///
/// 说明：
/// - 复用 kdf 参数（salt 不变）。
/// - nonce 每次重新生成。
pub fn encrypt_with_derived_key(
    plain: &KeyStorePlain,
    kdf: &KdfParams,
    derived_key: &[u8; 32],
) -> Result<KeyStoreFile, KeyStoreError> {
    // 只支持我们当前实现的算法。
    if kdf.algorithm != "argon2id" {
        return Err(KeyStoreError::Crypto(format!(
            "不支持的 KDF：{}",
            kdf.algorithm
        )));
    }

    let plaintext = serde_json::to_vec(plain)?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // 密钥库 AEAD：统一使用 AES-256-GCM（nonce 12 字节）。
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(derived_key));
    let ciphertext = cipher
        .encrypt(AesNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| KeyStoreError::PasswordOrDataInvalid)?;

    Ok(KeyStoreFile::Encrypted {
        version: KEYSTORE_VERSION,
        kdf: kdf.clone(),
        aead: AeadParams {
            algorithm: "aes256gcm".to_string(),
            nonce_b64: B64.encode(nonce),
        },
        ciphertext_b64: B64.encode(ciphertext),
    })
}

/// 将密钥库写回磁盘（明文）。
pub fn write_plain(app: &AppHandle, plain: &KeyStorePlain) -> Result<(), KeyStoreError> {
    let path = keystore_path(app)?;
    let file = KeyStoreFile::Plain {
        version: KEYSTORE_VERSION,
        data: plain.clone(),
    };
    write_json_atomic(&path, &file)
}

/// 将密钥库写回磁盘（加密）。
pub fn write_encrypted(
    app: &AppHandle,
    plain: &KeyStorePlain,
    kdf: &KdfParams,
    derived_key: &[u8; 32],
) -> Result<(), KeyStoreError> {
    let path = keystore_path(app)?;
    let file = encrypt_with_derived_key(plain, kdf, derived_key)?;
    write_json_atomic(&path, &file)
}

/// 用“新密码”启用/修改应用锁：生成新 salt，并返回 (kdf, derived_key)。
pub fn encrypt_with_new_password(
    plain: &KeyStorePlain,
    password: &str,
) -> Result<(KeyStoreFile, KdfParams, [u8; 32]), KeyStoreError> {
    let plaintext = serde_json::to_vec(plain)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key_bytes = [0u8; 32];
    derive_key_argon2id(password, &salt, &mut key_bytes)?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // 密钥库 AEAD：统一使用 AES-256-GCM（nonce 12 字节）。
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key_bytes));
    let ciphertext = cipher
        .encrypt(AesNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| KeyStoreError::PasswordOrDataInvalid)?;

    let kdf = KdfParams {
        algorithm: "argon2id".to_string(),
        salt_b64: B64.encode(salt),
        memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
        time_cost: DEFAULT_ARGON2_TIME_COST,
        parallelism: DEFAULT_ARGON2_PARALLELISM,
    };

    let file = KeyStoreFile::Encrypted {
        version: KEYSTORE_VERSION,
        kdf: kdf.clone(),
        aead: AeadParams {
            algorithm: "aes256gcm".to_string(),
            nonce_b64: B64.encode(nonce),
        },
        ciphertext_b64: B64.encode(ciphertext),
    };

    Ok((file, kdf, key_bytes))
}

/// 根据 id 找到密钥条目（只读）。
pub fn find_entry<'a>(plain: &'a KeyStorePlain, id: &str) -> Option<&'a KeyEntry> {
    plain.key_entries.iter().find(|e| e.id == id)
}

/// 根据 id 删除密钥条目。
pub fn delete_entry(plain: &mut KeyStorePlain, id: &str) -> bool {
    let before = plain.key_entries.len();
    plain.key_entries.retain(|e| e.id != id);
    before != plain.key_entries.len()
}

/// 生成随机 ID（用于密钥条目）。
///
/// 说明：
/// - 不引入额外 uuid 依赖，直接用 16 字节随机数 + Base64。
pub fn generate_entry_id() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

// =========================
// 下面是“解密/派生密钥”细节
// =========================

fn decrypt_keystore_return_key(
    kdf: &KdfParams,
    aead: &AeadParams,
    ciphertext_b64: &str,
    password: &str,
) -> Result<(KeyStorePlain, [u8; 32]), KeyStoreError> {
    if kdf.algorithm != "argon2id" {
        return Err(KeyStoreError::Crypto(format!(
            "不支持的 KDF：{}",
            kdf.algorithm
        )));
    }
    // 密钥库仅支持 AES-256-GCM（开发阶段不做向后兼容）。
    if aead.algorithm != "aes256gcm" {
        return Err(KeyStoreError::Crypto(format!(
            "不支持的 AEAD：{}",
            aead.algorithm
        )));
    }

    let salt = B64
        .decode(kdf.salt_b64.as_bytes())
        .map_err(|e| KeyStoreError::Crypto(format!("salt 解码失败：{e}")))?;

    let nonce = B64
        .decode(aead.nonce_b64.as_bytes())
        .map_err(|e| KeyStoreError::Crypto(format!("nonce 解码失败：{e}")))?;

    let ciphertext = B64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|e| KeyStoreError::Crypto(format!("ciphertext 解码失败：{e}")))?;

    if salt.len() != 16 || nonce.len() != 12 {
        return Err(KeyStoreError::PasswordOrDataInvalid);
    }

    let mut key_bytes = [0u8; 32];
    derive_key_argon2id_with_params(
        password,
        &salt,
        &mut key_bytes,
        kdf.memory_kib,
        kdf.time_cost,
        kdf.parallelism,
    )?;

    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(AesNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| KeyStoreError::PasswordOrDataInvalid)?;

    let plain: KeyStorePlain =
        serde_json::from_slice(&plaintext).map_err(|_| KeyStoreError::PasswordOrDataInvalid)?;

    if plain.version != KEYSTORE_VERSION {
        return Err(KeyStoreError::Crypto(format!(
            "密钥库版本不兼容：当前支持版本为 {}，文件版本为 {}",
            KEYSTORE_VERSION, plain.version
        )));
    }

    // plaintext 用完即可丢弃；key_bytes 返回给调用方缓存。
    Ok((plain, key_bytes))
}

fn derive_key_argon2id(
    password: &str,
    salt: &[u8],
    out_key_32: &mut [u8; 32],
) -> Result<(), KeyStoreError> {
    derive_key_argon2id_with_params(
        password,
        salt,
        out_key_32,
        DEFAULT_ARGON2_MEMORY_KIB,
        DEFAULT_ARGON2_TIME_COST,
        DEFAULT_ARGON2_PARALLELISM,
    )
}

fn derive_key_argon2id_with_params(
    password: &str,
    salt: &[u8],
    out_key_32: &mut [u8; 32],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<(), KeyStoreError> {
    let params = Params::new(memory_kib, time_cost, parallelism, Some(32))
        .map_err(|e| KeyStoreError::Crypto(format!("Argon2 参数错误：{e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, out_key_32)
        .map_err(|e| KeyStoreError::Crypto(format!("Argon2 派生失败：{e}")))?;

    Ok(())
}

fn write_json_atomic(path: &Path, value: &KeyStoreFile) -> Result<(), KeyStoreError> {
    let tmp = path.with_extension("json.tmp");

    let data = serde_json::to_vec_pretty(value)?;
    fs::write(&tmp, data)?;

    // Windows 下 rename 覆盖旧文件可能失败，所以先删除。
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;

    Ok(())
}
