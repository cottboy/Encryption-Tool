/*
  密钥库（KeyStore）：
  - 需求要求（已确认）：
    1) 单一密钥库：应用只管理“一个密钥库文件”。
    2) 密钥管理页进入后直接列出密钥，提供生成/导入/导出/删除等操作。
    3) 本项目已移除“应用锁/密钥库加密”功能：密钥库仅以明文 JSON 存储。

  本阶段重要变更（为了支持“算法模块化 + 任意字段扩展”）：
  - 旧版 KeyStore 使用“固定字段/固定枚举（RSA/X25519/对称）”存密钥材料，扩展新算法会卡死在结构体字段名上。
  - 新版 KeyStore 改为“通用 parts 结构”：
    - 一个密钥条目（KeyEntry）里保存 N 个零件（KeyPart）
    - 每个零件包含：id / encoding / value
  - 这样新增算法时：只要声明它需要哪些 parts，前端就能动态渲染输入框，后端也能原样存盘。

  文件与格式：
  - 存储路径：AppData/keystore.json
  - JSON 容器：
    - 明文：{ format: "plain", data: {...} }

  说明：
  - 由于已移除“密钥库加密/解锁”，本模块不再包含任何 KDF/AEAD 相关实现。
  - 若用户磁盘上仍残留旧版加密密钥库文件（format=encrypted），将被视为不支持格式并提示删除重建。
*/

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// 密钥库文件名（固定单文件）。
const KEYSTORE_FILENAME: &str = "keystore.json";

/// 密钥库内部数据（明文部分）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStorePlain {
    /// 密钥条目列表。
    pub key_entries: Vec<KeyEntry>,
}

/// KeyPart 的编码类型：用于表达 value 的语义（Base64/PEM/Hex/UTF8）。
///
/// 说明：
/// - encoding 的存在不是为了“强制限制”，而是为了让算法模块能做一致的解析/校验；
/// - 未来新增算法时可以继续复用这些 encoding，不需要改 KeyStore 结构。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPartEncoding {
    /// Base64：用于二进制材料（例如对称密钥、X25519 公私钥）。
    Base64,
    /// Hex：用于二进制材料的十六进制文本表示（可选）。
    Hex,
    /// PEM：用于 RSA 公私钥等 PEM 文本。
    Pem,
    /// UTF-8：用于纯文本类材料（按你的要求新增）。
    Utf8,
}

/// 通用“密钥零件（part）”：KeyEntry 的可扩展材料载体。
///
/// 设计目标：
/// - 不再为每一种算法/材料在后端写死字段名；
/// - 通过 parts 列表实现“新增算法只新增一个算法文件 + 声明 parts”。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPart {
    /// 零件 id：由算法文件声明并与前端表单绑定（例如 rsa_public_pem）。
    pub id: String,
    /// 零件编码：用于算法模块解析 value。
    pub encoding: KeyPartEncoding,
    /// 零件值：具体内容（例如 Base64 字符串 / PEM 文本 / Hex 文本 / UTF-8 文本）。
    pub value: String,
}

/// 单个密钥条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// 条目 ID：用于 UI 选择与后端定位。
    pub id: String,

    /// 用户可读名称。
    pub label: String,

    /// 密钥类型（例如 AES-256 / ChaCha20 / RSA-2048 / RSA-4096 / X25519）。
    pub key_type: String,

    /// 通用 parts：该密钥条目包含的所有材料零件。
    pub parts: Vec<KeyPart>,
}

/// 密钥库文件（磁盘上的 JSON 容器）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum KeyStoreFile {
    Plain {
        data: KeyStorePlain,
    },
}

/// 给前端展示的密钥库状态（不包含敏感材料）。
#[derive(Debug, Clone, Serialize)]
pub struct KeyStoreStatus {
    pub exists: bool,
    pub key_count: Option<usize>,
}

/// KeyStore 相关错误：统一转成字符串返回给前端。
#[derive(Debug)]
pub enum KeyStoreError {
    NotFound,
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStoreError::NotFound => write!(f, "密钥库不存在"),
            KeyStoreError::Io(e) => write!(f, "文件读写错误：{e}"),
            KeyStoreError::Json(e) => write!(f, "JSON 解析错误：{e}"),
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
        key_entries: Vec::new(),
    };

    let file = KeyStoreFile::Plain { data: plain };

    write_json_atomic(&path, &file)?;
    Ok(())
}

/// 读取密钥库明文：直接按当前结构读取。
pub fn read_plain(app: &AppHandle) -> Result<KeyStorePlain, KeyStoreError> {
    let path = keystore_path(app)?;
    if !path.exists() {
        return Err(KeyStoreError::NotFound);
    }

    let bytes = fs::read(path)?;
    let file: KeyStoreFile = serde_json::from_slice(&bytes)?;
    match file {
        KeyStoreFile::Plain { data } => Ok(data),
    }
}

/// 获取密钥库状态（不包含敏感材料）。
pub fn status(app: &AppHandle) -> Result<KeyStoreStatus, KeyStoreError> {
    let path = keystore_path(app)?;
    if !path.exists() {
        return Ok(KeyStoreStatus {
            exists: false,
            key_count: Some(0),
        });
    }

    let plain = read_plain(app)?;
    Ok(KeyStoreStatus {
        exists: true,
        key_count: Some(plain.key_entries.len()),
    })
}

/// 将密钥库写回磁盘（明文）。
pub fn write_plain(app: &AppHandle, plain: &KeyStorePlain) -> Result<(), KeyStoreError> {
    let path = keystore_path(app)?;
    let file = KeyStoreFile::Plain { data: plain.clone() };
    write_json_atomic(&path, &file)
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

/// 在条目中按 part id 查找零件（只读）。
///
/// 说明：
/// - parts 是可扩展列表，因此我们用线性查找即可（当前规模很小）；
/// - 若未来 parts 很多，再考虑引入 Map 缓存（但目前不必过度设计）。
pub fn find_part<'a>(entry: &'a KeyEntry, id: &str) -> Option<&'a KeyPart> {
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    entry.parts.iter().find(|p| p.id == id)
}

/// 判断条目是否包含某个 part（用于“密钥完整度”判断）。
pub fn has_part(entry: &KeyEntry, id: &str) -> bool {
    find_part(entry, id)
        .map(|p| p.value.trim())
        .filter(|v| !v.is_empty())
        .is_some()
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
