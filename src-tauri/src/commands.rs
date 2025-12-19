/*
  Tauri 命令集合：
  - 原则：
    1) 前端只做 UI 与参数收集
    2) 密钥生成/导入/导出/持久化全部在 Rust 后端完成

  本阶段命令重点：
  - 单一密钥库（一个 keystore.json）
  - 支持密钥生成/导入/导出：AES-256 / ChaCha20 / RSA / X25519
  - 支持应用锁（密钥库加密）：启用后启动必须解锁
*/

use std::fs;

use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::{keystore, state::AppState, state::UnlockedKeystore, text_crypto};

// =====================
// 基础命令（用于连通性）
// =====================

#[tauri::command]
pub fn health_check() -> &'static str {
    "ok"
}

// =====================
// 算法列表（用于 UI 初始化）
// =====================

#[derive(Debug, Serialize)]
pub struct SupportedAlgorithms {
    /// 对称加密算法（文本/文件都可用；文件场景会实现流式分块）。
    pub symmetric: Vec<&'static str>,

    /// 非对称/密钥协商算法（实际会走混合加密）。
    pub asymmetric: Vec<&'static str>,
}

#[tauri::command]
pub fn get_supported_algorithms() -> SupportedAlgorithms {
    SupportedAlgorithms {
        symmetric: vec!["AES-256", "ChaCha20"],
        asymmetric: vec!["RSA", "X25519"],
    }
}

// =====================
// 应用锁 / 密钥库（KeyStore）
// =====================

/// 给前端展示的密钥条目（不包含敏感材料）。
#[derive(Debug, Serialize)]
pub struct KeyEntryPublic {
    /// 条目 ID：仅用于前后端交互与定位；UI 不展示。
    pub id: String,

    /// 用户可读名称：导入/生成时由用户设置。
    pub label: String,

    /// 密钥类型（算法）：例如 AES-256 / ChaCha20 / RSA / X25519。
    pub key_type: String,

    /// 材料类型：用于前端决定“可预览/可导出”的具体格式。
    /// - symmetric：对称密钥
    /// - rsa_private：RSA 私钥（含公钥）
    /// - rsa_public：RSA 公钥
    /// - x25519：X25519 私钥（含公钥）
    pub material_kind: String,
}
/// 获取密钥库状态：
/// - 若首次启动没有密钥库文件，会自动创建一个明文空库。
#[tauri::command]
pub fn keystore_status(app: AppHandle, state: State<'_, AppState>) -> Result<keystore::KeyStoreStatus, String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;

    // 只有在“密钥库已加密”的情况下，unlocked 才有意义；
    // 这里用 state 中是否存在 Encrypted 会话来判断。
    let unlocked = {
        let guard = state
            .unlocked_keystore
            .lock()
            .map_err(|_| "内部错误：状态锁被占用".to_string())?;

        matches!(&*guard, Some(UnlockedKeystore::Encrypted { .. }))
    };

    keystore::status(&app, unlocked).map_err(|e| e.to_string())
}

/// 解锁密钥库：
/// - 若为明文库：直接读取并缓存 Plain 会话。
/// - 若为加密库：解密并缓存 Encrypted 会话（含派生密钥）。
#[tauri::command]
pub fn keystore_unlock(app: AppHandle, state: State<'_, AppState>, password: String) -> Result<(), String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;

    let (plain, derived) =
        keystore::decrypt_with_password_and_derived_key(&app, password.trim()).map_err(|e| e.to_string())?;

    let mut guard = state
        .unlocked_keystore
        .lock()
        .map_err(|_| "内部错误：状态锁被占用".to_string())?;

    *guard = match derived {
        None => Some(UnlockedKeystore::Plain(plain)),
        Some((kdf, key)) => Some(UnlockedKeystore::Encrypted {
            plain,
            kdf,
            derived_key: Zeroizing::new(key),
        }),
    };

    Ok(())
}

/// 主动锁定：清空会话缓存。
#[tauri::command]
pub fn keystore_lock(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .unlocked_keystore
        .lock()
        .map_err(|_| "内部错误：状态锁被占用".to_string())?;

    *guard = None;
    Ok(())
}

/// 设置/移除应用锁：
/// - new_password=Some：启用或修改应用锁
/// - new_password=None：移除应用锁
#[tauri::command]
pub fn keystore_set_lock(
    app: AppHandle,
    state: State<'_, AppState>,
    new_password: Option<String>,
) -> Result<(), String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;

    // 先拿到当前密钥库明文：
    // - 未加密：从文件读取
    // - 已加密：必须已解锁（从 state 读取）
    let (plain, current_encrypted_ctx) = load_plain_for_write(&app, &state)?;

    match new_password.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(pw) => {
            // 启用/修改应用锁：用新密码加密并写回。
            let (file, kdf, key) = keystore::encrypt_with_new_password(&plain, pw).map_err(|e| e.to_string())?;
            let path = keystore::keystore_path(&app).map_err(|e| e.to_string())?;
            write_file_atomic(&path, &file).map_err(|e| e.to_string())?;

            // 更新会话：保存派生密钥，便于后续写回。
            let mut guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            *guard = Some(UnlockedKeystore::Encrypted {
                plain,
                kdf,
                derived_key: Zeroizing::new(key),
            });
            Ok(())
        }
        None => {
            // 移除应用锁：写回明文。
            keystore::write_plain(&app, &plain).map_err(|e| e.to_string())?;

            // 更新会话：改为 Plain。
            let mut guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            *guard = Some(UnlockedKeystore::Plain(plain));

            // current_encrypted_ctx 用不到，但保持返回签名一致。
            drop(current_encrypted_ctx);
            Ok(())
        }
    }
}

/// 列出密钥条目（不包含敏感材料）。
/// - 未加密：直接读取文件
/// - 已加密：必须先解锁（从 state 读取）
#[tauri::command]
pub fn keystore_list_entries(app: AppHandle, state: State<'_, AppState>) -> Result<Vec<KeyEntryPublic>, String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;

    let file = keystore::read_file(&app).map_err(|e| e.to_string())?;

    let plain = match file {
        keystore::KeyStoreFile::Plain { data, .. } => data,
        keystore::KeyStoreFile::Encrypted { .. } => {
            let guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            match &*guard {
                Some(UnlockedKeystore::Encrypted { plain, .. }) => plain.clone(),
                _ => return Err(keystore::KeyStoreError::PasswordRequired.to_string()),
            }
        }
    };

    let entries = plain
        .key_entries
        .iter()
        .map(|e| {
            let material_kind = match &e.material {
                keystore::KeyMaterial::Symmetric { .. } => "symmetric",
                keystore::KeyMaterial::RsaPrivate { .. } => "rsa_private",
                keystore::KeyMaterial::RsaPublic { .. } => "rsa_public",
                keystore::KeyMaterial::X25519 { .. } => "x25519",
            }
            .to_string();

            KeyEntryPublic {
                id: e.id.clone(),
                label: e.label.clone(),
                key_type: e.key_type.clone(),
                material_kind,
            }
        })
        .collect();

    Ok(entries)
}

// =====================
// 密钥：生成 / 导入 / 导出 / 删除
// =====================

#[derive(Debug, Deserialize)]
pub struct GenerateKeyRequest {
    pub key_type: String,
    pub label: Option<String>,
}

#[tauri::command]
pub fn keystore_generate_key(
    app: AppHandle,
    state: State<'_, AppState>,
    req: GenerateKeyRequest,
) -> Result<KeyEntryPublic, String> {
    let key_type = req.key_type.trim();
    if key_type.is_empty() {
        return Err("key_type 不能为空".to_string());
    }

    let label = req
        .label
        .unwrap_or_default()
        .trim()
        .to_string();

    with_plain_mutation(&app, &state, |plain| {
        let id = keystore::generate_entry_id();

        let entry_label = if label.is_empty() {
            format!("{key_type} 密钥")
        } else {
            label
        };

        let entry = match key_type {
            "AES-256" | "ChaCha20" => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: key_type.to_string(),
                    material: keystore::KeyMaterial::Symmetric { key_b64 },
                }
            }
            "X25519" => {
                let mut secret_bytes = [0u8; 32];
                OsRng.fill_bytes(&mut secret_bytes);
                let secret = X25519StaticSecret::from(secret_bytes);
                let public = X25519PublicKey::from(&secret);

                let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret_bytes);
                let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: "X25519".to_string(),
                    material: keystore::KeyMaterial::X25519 { secret_b64, public_b64 },
                }
            }
            "RSA" => {
                // RSA 参数：先用 2048 位，兼顾安全性与性能。
                let private = RsaPrivateKey::new(&mut OsRng, 2048)
                    .map_err(|e| format!("RSA 生成失败：{e}"))?;
                let public = RsaPublicKey::from(&private);

                let private_pem = private
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                    .to_string();

                let public_pem = public
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                    .to_string();

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: "RSA".to_string(),
                    material: keystore::KeyMaterial::RsaPrivate { private_pem, public_pem },
                }
            }
            _ => return Err(format!("不支持的 key_type：{key_type}")),
        };

        plain.key_entries.push(entry);

        // 返回给前端的“公共信息”，不包含任何敏感材料。
        // material_kind 用于 UI 决定导出/预览可用的格式。
        let material_kind = match key_type {
            "RSA" => "rsa_private".to_string(),
            "X25519" => "x25519".to_string(),
            _ => "symmetric".to_string(),
        };

        Ok(KeyEntryPublic {
            id,
            label: entry_label.clone(),
            key_type: key_type.to_string(),
            material_kind,
        })
    })
}

#[derive(Debug, Deserialize)]
pub struct ImportKeyRequest {
    pub key_type: String,
    pub label: Option<String>,
    pub path: String,
}

#[tauri::command]
pub fn keystore_import_key(app: AppHandle, state: State<'_, AppState>, req: ImportKeyRequest) -> Result<KeyEntryPublic, String> {
    let key_type = req.key_type.trim();
    if key_type.is_empty() {
        return Err("key_type 不能为空".to_string());
    }

    let path = req.path.trim();
    if path.is_empty() {
        return Err("path 不能为空".to_string());
    }

    let label = req.label.unwrap_or_default().trim().to_string();

    let bytes = fs::read(path).map_err(|e| format!("读取文件失败：{e}"))?;
    let text = String::from_utf8_lossy(&bytes).to_string();

    with_plain_mutation(&app, &state, |plain| {
        let id = keystore::generate_entry_id();

        let entry_label = if label.is_empty() {
            format!("{key_type} 导入")
        } else {
            label
        };

        let entry = match key_type {
            "AES-256" | "ChaCha20" => {
                let raw = text.trim();
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(raw.as_bytes())
                    .map_err(|e| format!("Base64 解码失败：{e}"))?;
                if decoded.len() != 32 {
                    return Err("对称密钥长度必须为 32 字节（Base64 解码后）".to_string());
                }
                let key_b64 = base64::engine::general_purpose::STANDARD.encode(decoded);
                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: key_type.to_string(),
                    material: keystore::KeyMaterial::Symmetric { key_b64 },
                }
            }
            "X25519" => {
                // 优先尝试 JSON（我们自己的导出格式）。
                #[derive(Deserialize)]
                struct X25519Json {
                    secret_b64: String,                }

                let maybe_json: Result<X25519Json, _> = serde_json::from_str(text.trim());
                let secret_bytes: [u8; 32] = if let Ok(j) = maybe_json {
                    let secret = base64::engine::general_purpose::STANDARD
                        .decode(j.secret_b64.as_bytes())
                        .map_err(|e| format!("X25519 secret_b64 解码失败：{e}"))?;
                    if secret.len() != 32 {
                        return Err("X25519 私钥必须为 32 字节".to_string());
                    }
                    secret.as_slice().try_into().map_err(|_| "X25519 私钥长度错误".to_string())?
                } else {
                    // 退化：允许用户直接导入“Base64 编码的 32 字节私钥”。
                    let secret = base64::engine::general_purpose::STANDARD
                        .decode(text.trim().as_bytes())
                        .map_err(|e| format!("X25519 Base64 解码失败：{e}"))?;
                    if secret.len() != 32 {
                        return Err("X25519 私钥必须为 32 字节（Base64 解码后）".to_string());
                    }
                    secret.as_slice().try_into().map_err(|_| "X25519 私钥长度错误".to_string())?
                };

                let secret = X25519StaticSecret::from(secret_bytes);
                let public = X25519PublicKey::from(&secret);

                let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret_bytes);
                let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: "X25519".to_string(),
                    material: keystore::KeyMaterial::X25519 { secret_b64, public_b64 },
                }
            }
            "RSA" => {
                let trimmed = text.trim();

                // 先尝试 PKCS8 私钥。
                if let Ok(private) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
                    let public = RsaPublicKey::from(&private);
                    let private_pem = private
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                        .to_string();
                    let public_pem = public
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: "RSA".to_string(),
                        material: keystore::KeyMaterial::RsaPrivate { private_pem, public_pem },
                    }
                }
                // 再尝试 PKCS1 私钥（BEGIN RSA PRIVATE KEY）。
                else if let Ok(private) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
                    let public = RsaPublicKey::from(&private);
                    let private_pem = private
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                        .to_string();
                    let public_pem = public
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: "RSA".to_string(),
                        material: keystore::KeyMaterial::RsaPrivate { private_pem, public_pem },
                    }
                }
                // 最后尝试公钥（BEGIN PUBLIC KEY）。
                else if let Ok(public) = RsaPublicKey::from_public_key_pem(trimmed) {
                    let public_pem = public
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: "RSA".to_string(),
                        material: keystore::KeyMaterial::RsaPublic { public_pem },
                    }
                } else {
                    return Err("无法识别 RSA 密钥格式（支持 PKCS8/PKCS1 私钥 PEM 或公钥 PEM）".to_string());
                }
            }
            _ => return Err(format!("不支持的 key_type：{key_type}")),
        };

        plain.key_entries.push(entry);

        Ok(KeyEntryPublic { id, label: entry_label.clone(), key_type: key_type.to_string(), material_kind: match key_type { "RSA" => "rsa_private".to_string(), "X25519" => "x25519".to_string(), _ => "symmetric".to_string() } })
    })
}

#[derive(Debug, Deserialize)]
pub struct ExportKeyRequest {
    pub id: String,
    /// 导出格式：
    /// - AES-256/ChaCha20："key_b64"
    /// - RSA："private_pem" | "public_pem"
    /// - X25519："json" | "public_b64"
    pub format: String,
    pub path: String,
}

#[tauri::command]
pub fn keystore_export_key(app: AppHandle, state: State<'_, AppState>, req: ExportKeyRequest) -> Result<(), String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }
    let path = req.path.trim();
    if path.is_empty() {
        return Err("path 不能为空".to_string());
    }

    // 读取密钥库明文（导出不修改，因此这里用只读即可）。
    let plain = load_plain_for_read(&app, &state)?;

    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到指定的密钥".to_string())?;

    let output = match (&entry.key_type[..], &entry.material, req.format.as_str()) {
        ("AES-256" | "ChaCha20", keystore::KeyMaterial::Symmetric { key_b64 }, "key_b64") => {
            key_b64.clone()
        }
        ("RSA", keystore::KeyMaterial::RsaPrivate { private_pem, .. }, "private_pem") => private_pem.clone(),
        ("RSA", keystore::KeyMaterial::RsaPrivate { public_pem, .. }, "public_pem") => public_pem.clone(),
        ("RSA", keystore::KeyMaterial::RsaPublic { public_pem }, "public_pem") => public_pem.clone(),
        ("X25519", keystore::KeyMaterial::X25519 { public_b64, .. }, "public_b64") => public_b64.clone(),
        ("X25519", keystore::KeyMaterial::X25519 { secret_b64, public_b64 }, "json") => {
            #[derive(Serialize)]
            struct X25519Export<'a> {
                secret_b64: &'a str,
                public_b64: &'a str,
            }
            serde_json::to_string_pretty(&X25519Export {
                secret_b64,
                public_b64,
            })
            .map_err(|e| format!("JSON 序列化失败：{e}"))?
        }
        _ => return Err("导出格式与密钥类型不匹配".to_string()),
    };

    fs::write(path, output).map_err(|e| format!("写入导出文件失败：{e}"))?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct DeleteKeyRequest {
    pub id: String,
}

#[tauri::command]
pub fn keystore_delete_key(app: AppHandle, state: State<'_, AppState>, req: DeleteKeyRequest) -> Result<(), String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    with_plain_mutation(&app, &state, |plain| {
        let removed = keystore::delete_entry(plain, id);
        if !removed {
            return Err("未找到指定的密钥".to_string());
        }
        Ok(())
    })
}

// =====================
// 内部辅助：读取/写入与加密写回
// =====================

/// 只读获取密钥库明文：
/// - 未加密：从文件读取
/// - 已加密：必须已解锁（从 state 读取）
fn load_plain_for_read(app: &AppHandle, state: &State<'_, AppState>) -> Result<keystore::KeyStorePlain, String> {
    let file = keystore::read_file(app).map_err(|e| e.to_string())?;
    match file {
                keystore::KeyStoreFile::Plain { data, .. } => {
            let guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            match &*guard {
                Some(UnlockedKeystore::Plain(p)) => Ok(p.clone()),
                _ => Ok(data),
            }
        },
        keystore::KeyStoreFile::Encrypted { .. } => {
            let guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            match &*guard {
                Some(UnlockedKeystore::Encrypted { plain, .. }) => Ok(plain.clone()),
                _ => Err(keystore::KeyStoreError::PasswordRequired.to_string()),
            }
        }
    }
}

/// 写操作获取明文与加密上下文：
/// - 返回 (plain, Option<(kdf, derived_key)>)
fn load_plain_for_write(
    app: &AppHandle,
    state: &State<'_, AppState>,
) -> Result<(keystore::KeyStorePlain, Option<(keystore::KdfParams, Zeroizing<[u8; 32]>)>), String> {
    let file = keystore::read_file(app).map_err(|e| e.to_string())?;

    match file {
                keystore::KeyStoreFile::Plain { data, .. } => {
            let guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            match &*guard {
                Some(UnlockedKeystore::Plain(p)) => Ok((p.clone(), None)),
                _ => Ok((data, None)),
            }
        }
        keystore::KeyStoreFile::Encrypted { .. } => {
            let guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            match &*guard {
                Some(UnlockedKeystore::Encrypted {
                    plain,
                    kdf,
                    derived_key,
                }) => Ok((plain.clone(), Some((kdf.clone(), derived_key.clone())))),
                _ => Err(keystore::KeyStoreError::PasswordRequired.to_string()),
            }
        }
    }
}

/// 对密钥库明文进行一次“可持久化的修改”：
/// - 会根据当前密钥库是否加密，写回明文或加密文件
/// - 若为加密库，会同时更新 state 中缓存的明文
fn with_plain_mutation<T>(
    app: &AppHandle,
    state: &State<'_, AppState>,
    f: impl FnOnce(&mut keystore::KeyStorePlain) -> Result<T, String>,
) -> Result<T, String> {
    keystore::ensure_exists(app).map_err(|e| e.to_string())?;

    let (mut plain, ctx) = load_plain_for_write(app, state)?;
    let out = f(&mut plain)?;

        match ctx {
        None => {
            keystore::write_plain(app, &plain).map_err(|e| e.to_string())?;

            // 明文库也缓存一份：
            // - 目的：减少重复读文件
            // - 同时可消除“Plain variant 未使用”的告警
            let mut guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;
            *guard = Some(UnlockedKeystore::Plain(plain.clone()));
        }
        Some((kdf, derived_key)) => {
            keystore::write_encrypted(app, &plain, &kdf, &derived_key).map_err(|e| e.to_string())?;

            // 写回成功后，更新 state 中的明文缓存。
            let mut guard = state
                .unlocked_keystore
                .lock()
                .map_err(|_| "内部错误：状态锁被占用".to_string())?;

            if let Some(UnlockedKeystore::Encrypted { plain: p, .. }) = &mut *guard {
                *p = plain.clone();
            }
        }
    }

    Ok(out)
}

/// 原子写入：用于写入加密库文件（KeyStoreFile）。
fn write_file_atomic(path: &std::path::Path, file: &keystore::KeyStoreFile) -> Result<(), keystore::KeyStoreError> {
    // 复用 keystore 内部的序列化与原子写策略：这里简单实现一份，避免暴露内部函数。
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(file)?;
    fs::write(&tmp, data)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}


#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyPreview {
    Symmetric {
        label: String,
        algorithm: String,
        key_b64: String,
    },
    Rsa {
        label: String,
        material_kind: String,
        public_pem: String,
        private_pem: Option<String>,
    },
    X25519 {
        label: String,
        public_b64: String,
        secret_b64: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct GetKeyPreviewRequest {
    pub id: String,
}

#[tauri::command]
pub fn keystore_get_key_preview(app: AppHandle, state: State<'_, AppState>, req: GetKeyPreviewRequest) -> Result<KeyPreview, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    let plain = load_plain_for_read(&app, &state)?;
    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到该密钥".to_string())?;

    match &entry.material {
        keystore::KeyMaterial::Symmetric { key_b64 } => Ok(KeyPreview::Symmetric {
            label: entry.label.clone(),
            algorithm: entry.key_type.clone(),
            key_b64: key_b64.clone(),
        }),
        keystore::KeyMaterial::RsaPrivate { private_pem, public_pem } => Ok(KeyPreview::Rsa {
            label: entry.label.clone(),
            material_kind: "rsa_private".to_string(),
            public_pem: public_pem.clone(),
            private_pem: Some(private_pem.clone()),
        }),
        keystore::KeyMaterial::RsaPublic { public_pem } => Ok(KeyPreview::Rsa {
            label: entry.label.clone(),
            material_kind: "rsa_public".to_string(),
            public_pem: public_pem.clone(),
            private_pem: None,
        }),
        keystore::KeyMaterial::X25519 { secret_b64, public_b64 } => Ok(KeyPreview::X25519 {
            label: entry.label.clone(),
            public_b64: public_b64.clone(),
            secret_b64: secret_b64.clone(),
        }),
    }
}

// =====================
// 文本加密/解密（后端执行）
// =====================

/// 文本加密请求：前端只传“算法 + 密钥 + 明文”，加密全部在后端完成。
#[derive(Debug, Deserialize)]
pub struct TextEncryptRequest {
    /// 选择的算法：AES-256 / ChaCha20 / RSA / X25519
    pub algorithm: String,
    /// 密钥库条目 id
    pub key_id: String,
    /// 明文输入（UTF-8）
    pub plaintext: String,
}

/// 文本解密请求：前端只传“算法 + 密钥 + 密文(JSON)”，解密全部在后端完成。
#[derive(Debug, Deserialize)]
pub struct TextDecryptRequest {
    /// 选择的算法：AES-256 / ChaCha20 / RSA / X25519
    pub algorithm: String,
    /// 密钥库条目 id
    pub key_id: String,
    /// 密文输入（JSON 自描述容器）
    pub ciphertext: String,
}

/// 文本加密：返回 JSON 密文与“是否混合加密”提示位。
#[tauri::command]
pub fn text_encrypt(app: AppHandle, state: State<'_, AppState>, req: TextEncryptRequest) -> Result<text_crypto::TextEncryptResponse, String> {
    // 读取密钥库明文：若密钥库已加密但未解锁，这里会返回“需要输入密码解锁”。
    let plain = load_plain_for_read(&app, &state)?;

    // 调用专用模块执行加密：避免 commands.rs 继续膨胀。
    text_crypto::encrypt_text(&plain, &req.algorithm, &req.key_id, &req.plaintext)
}

/// 文本解密：返回明文；解密失败统一提示“密钥错误或数据已损坏”。
#[tauri::command]
pub fn text_decrypt(app: AppHandle, state: State<'_, AppState>, req: TextDecryptRequest) -> Result<text_crypto::TextDecryptResponse, String> {
    // 读取密钥库明文：若密钥库已加密但未解锁，这里会返回“需要输入密码解锁”。
    let plain = load_plain_for_read(&app, &state)?;

    // 调用专用模块执行解密：内部已做错误收敛处理。
    text_crypto::decrypt_text(&plain, &req.algorithm, &req.key_id, &req.ciphertext)
}
