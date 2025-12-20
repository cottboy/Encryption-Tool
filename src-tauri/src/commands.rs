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
use rsa::traits::PublicKeyParts;
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
        // 非对称算法：
        // - 需求变更：原来的 RSA 改名为 RSA2048，并新增 RSA4096（逻辑保持一致，仅密钥长度不同）。
        asymmetric: vec!["RSA2048", "RSA4096", "X25519"],
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
    ///
    /// 需求变更：前端需要在列表中展示“仅公钥/仅私钥/完整”等状态，因此这里更细分：
    /// - symmetric
    /// - rsa_public_only / rsa_private_only / rsa_full
    /// - x25519_public_only / x25519_secret_only / x25519_full
    pub material_kind: String,
}

/// 将“历史遗留的算法名”规范化为当前 UI 使用的算法名。
///
/// 说明：
/// - 需求变更要求把原来的 `RSA` 改名为 `RSA2048`。
/// - 为了不让旧 keystore 里的条目在新 UI 中“消失”（筛选条件是 key_type 相等），
///   这里在返回给前端时做一次归一化。
fn normalize_key_type_for_ui(key_type: &str) -> String {
    match key_type.trim() {
        "RSA" => "RSA2048".to_string(),
        other => other.to_string(),
    }
}

/// 将 keystore 明文数据中的“旧算法名”原地升级为新算法名。
///
/// 说明：
/// - 我们不在读取时强制写回磁盘（避免无意义的 IO）。
/// - 但在任何“写操作”发生时，顺手把旧数据规范化，这样用户的 keystore 会逐步被升级。
fn normalize_key_type_in_place(plain: &mut keystore::KeyStorePlain) {
    for e in &mut plain.key_entries {
        if e.key_type.trim() == "RSA" {
            e.key_type = "RSA2048".to_string();
        }
    }
}

/// 根据条目的材料，计算一个更细粒度的 `material_kind` 给前端做展示/能力判断。
///
/// 约定：
/// - symmetric
/// - rsa_public_only / rsa_private_only / rsa_full
/// - x25519_public_only / x25519_secret_only / x25519_full
fn material_kind_for_entry(entry: &keystore::KeyEntry) -> String {
    match &entry.material {
        keystore::KeyMaterial::Symmetric { .. } => "symmetric".to_string(),
        keystore::KeyMaterial::RsaPublic { .. } => "rsa_public_only".to_string(),
        keystore::KeyMaterial::RsaPrivate { public_pem, .. } => {
            if public_pem.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).is_some() {
                "rsa_full".to_string()
            } else {
                "rsa_private_only".to_string()
            }
        }
        keystore::KeyMaterial::X25519 { secret_b64, public_b64 } => {
            let has_secret = secret_b64.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).is_some();
            let has_public = public_b64.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).is_some();
            match (has_public, has_secret) {
                (true, true) => "x25519_full".to_string(),
                (true, false) => "x25519_public_only".to_string(),
                (false, true) => "x25519_secret_only".to_string(),
                (false, false) => "x25519_secret_only".to_string(), // 防御：不应出现，两者都缺失按“缺失”处理
            }
        }
    }
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
            let material_kind = material_kind_for_entry(e);

            KeyEntryPublic {
                id: e.id.clone(),
                label: e.label.clone(),
                // 兼容旧数据：把 RSA 归一化成 RSA2048，避免前端筛选不到。
                key_type: normalize_key_type_for_ui(&e.key_type),
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
        // 写操作前，顺手把旧数据里的 RSA 升级成 RSA2048，避免混用。
        normalize_key_type_in_place(plain);

        let id = keystore::generate_entry_id();

        let entry_label = if label.is_empty() {
            format!("{key_type} 密钥")
        } else {
            label
        };

        // 生成密钥：
        // - 对称：随机 32 字节
        // - X25519：随机 32 字节私钥 + 对应公钥
        // - RSA：按位数生成（2048/4096）
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
                    material: keystore::KeyMaterial::X25519 {
                        secret_b64: Some(secret_b64),
                        public_b64: Some(public_b64),
                    },
                }
            }
            "RSA" | "RSA2048" | "RSA4096" => {
                // RSA 参数：
                // - 需求变更：原 RSA 改名为 RSA2048；新增 RSA4096。
                // - 逻辑保持不变，仅密钥位数不同。
                let bits = match key_type {
                    "RSA4096" => 4096,
                    _ => 2048,
                };

                let normalized = if key_type == "RSA" { "RSA2048" } else { key_type };

                let private = RsaPrivateKey::new(&mut OsRng, bits)
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
                    key_type: normalized.to_string(),
                    material: keystore::KeyMaterial::RsaPrivate {
                        private_pem,
                        public_pem: Some(public_pem),
                    },
                }
            }
            _ => return Err(format!("不支持的 key_type：{key_type}")),
        };

        plain.key_entries.push(entry);

        // 返回给前端的“公共信息”，不包含任何敏感材料。
        // material_kind 用于 UI 展示“仅公钥/仅私钥/完整”等状态。
        let last = plain
            .key_entries
            .last()
            .ok_or_else(|| "内部错误：生成后未找到条目".to_string())?;
        let material_kind = material_kind_for_entry(last);

        Ok(KeyEntryPublic {
            id,
            label: entry_label.clone(),
            key_type: normalize_key_type_for_ui(key_type),
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
        // 写操作前，顺手把旧数据里的 RSA 升级成 RSA2048，避免混用。
        normalize_key_type_in_place(plain);

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
                //
                // 需求变更：允许只导入公钥或只导入私钥，因此字段都为可选。
                #[derive(Deserialize)]
                struct X25519Json {
                    secret_b64: Option<String>,
                    public_b64: Option<String>,
                }

                let trimmed = text.trim();
                let maybe_json: Result<X25519Json, _> = serde_json::from_str(trimmed);

                // 兼容旧行为：如果不是 JSON，则将其视为“Base64 编码的 32 字节私钥”。
                let (secret_b64, public_b64) = if let Ok(j) = maybe_json {
                    (j.secret_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                     j.public_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
                } else {
                    (Some(trimmed.to_string()), None)
                };

                if secret_b64.is_none() && public_b64.is_none() {
                    return Err("X25519 至少需要导入公钥或私钥".to_string());
                }

                // 基础校验：Base64 解码后必须为 32 字节。
                if let Some(s) = &secret_b64 {
                    let secret = base64::engine::general_purpose::STANDARD
                        .decode(s.as_bytes())
                        .map_err(|e| format!("X25519 私钥 Base64 解码失败：{e}"))?;
                    if secret.len() != 32 {
                        return Err("X25519 私钥必须为 32 字节（Base64 解码后）".to_string());
                    }
                }
                if let Some(s) = &public_b64 {
                    let public = base64::engine::general_purpose::STANDARD
                        .decode(s.as_bytes())
                        .map_err(|e| format!("X25519 公钥 Base64 解码失败：{e}"))?;
                    if public.len() != 32 {
                        return Err("X25519 公钥必须为 32 字节（Base64 解码后）".to_string());
                    }
                }

                // 如果用户同时给了私钥+公钥，做一次一致性校验，避免存进“对不上的一对”。
                if let (Some(secret_s), Some(public_s)) = (&secret_b64, &public_b64) {
                    let secret_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
                        .decode(secret_s.as_bytes())
                        .map_err(|e| format!("X25519 私钥 Base64 解码失败：{e}"))?
                        .as_slice()
                        .try_into()
                        .map_err(|_| "X25519 私钥长度错误".to_string())?;

                    let public_expect = X25519PublicKey::from(&X25519StaticSecret::from(secret_bytes));
                    let public_expect_b64 = base64::engine::general_purpose::STANDARD.encode(public_expect.as_bytes());

                    // 这里不做“自动修正”，而是提示用户输入不匹配，避免产生误解。
                    if public_expect_b64.trim() != public_s.trim() {
                        return Err("X25519 公钥与私钥不匹配".to_string());
                    }
                }

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: "X25519".to_string(),
                    material: keystore::KeyMaterial::X25519 { secret_b64, public_b64 },
                }
            }
            "RSA" | "RSA2048" | "RSA4096" => {
                // RSA 导入（文件方式）：
                // - 兼容：既支持私钥 PEM，也支持公钥 PEM。
                // - 需求变更：允许“仅公钥/仅私钥”。为了可控，这里不自动从私钥推导公钥。
                let bits_expected = match key_type {
                    "RSA4096" => Some(4096),
                    // 历史兼容：RSA 视为 RSA2048
                    "RSA" | "RSA2048" => Some(2048),
                    _ => None,
                };

                let trimmed = text.trim();

                // 先尝试 PKCS8 私钥。
                if let Ok(private) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
                    // 位数校验（可选）：避免用户把 2048 的材料导入成 RSA4096 之类的“挂羊头卖狗肉”。
                    if let Some(bits) = bits_expected {
                        if private.n().bits() as usize != bits {
                            return Err(format!("RSA 密钥位数不匹配：期望 {bits}，实际 {}", private.n().bits()));
                        }
                    }
                    let private_pem = private
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: normalize_key_type_for_ui(key_type),
                        material: keystore::KeyMaterial::RsaPrivate { private_pem, public_pem: None },
                    }
                }
                // 再尝试 PKCS1 私钥（BEGIN RSA PRIVATE KEY）。
                else if let Ok(private) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
                    if let Some(bits) = bits_expected {
                        if private.n().bits() as usize != bits {
                            return Err(format!("RSA 密钥位数不匹配：期望 {bits}，实际 {}", private.n().bits()));
                        }
                    }
                    let private_pem = private
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: normalize_key_type_for_ui(key_type),
                        material: keystore::KeyMaterial::RsaPrivate { private_pem, public_pem: None },
                    }
                }
                // 最后尝试公钥（BEGIN PUBLIC KEY）。
                else if let Ok(public) = RsaPublicKey::from_public_key_pem(trimmed) {
                    if let Some(bits) = bits_expected {
                        if public.n().bits() as usize != bits {
                            return Err(format!("RSA 密钥位数不匹配：期望 {bits}，实际 {}", public.n().bits()));
                        }
                    }
                    let public_pem = public
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: normalize_key_type_for_ui(key_type),
                        material: keystore::KeyMaterial::RsaPublic { public_pem },
                    }
                } else {
                    return Err("无法识别 RSA 密钥格式（支持 PKCS8/PKCS1 私钥 PEM 或公钥 PEM）".to_string());
                }
            }
            _ => return Err(format!("不支持的 key_type：{key_type}")),
        };

        plain.key_entries.push(entry);

        let last = plain
            .key_entries
            .last()
            .ok_or_else(|| "内部错误：导入后未找到条目".to_string())?;

        Ok(KeyEntryPublic {
            id,
            label: entry_label.clone(),
            key_type: normalize_key_type_for_ui(key_type),
            material_kind: material_kind_for_entry(last),
        })
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
        ("RSA" | "RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPrivate { private_pem, .. }, "private_pem") => private_pem.clone(),
        ("RSA" | "RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPrivate { public_pem, .. }, "public_pem") => {
            public_pem
                .clone()
                .ok_or_else(|| "该 RSA 条目缺少公钥，无法导出公钥".to_string())?
        }
        ("RSA" | "RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPublic { public_pem }, "public_pem") => public_pem.clone(),
        ("X25519", keystore::KeyMaterial::X25519 { public_b64, .. }, "public_b64") => {
            public_b64
                .clone()
                .ok_or_else(|| "该 X25519 条目缺少公钥，无法导出公钥".to_string())?
        }
        ("X25519", keystore::KeyMaterial::X25519 { secret_b64, public_b64 }, "json") => {
            #[derive(Serialize)]
            struct X25519Export<'a> {
                secret_b64: Option<&'a str>,
                public_b64: Option<&'a str>,
            }
            serde_json::to_string_pretty(&X25519Export {
                secret_b64: secret_b64.as_deref(),
                public_b64: public_b64.as_deref(),
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
        public_pem: Option<String>,
        private_pem: Option<String>,
    },
    X25519 {
        label: String,
        public_b64: Option<String>,
        secret_b64: Option<String>,
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
            algorithm: normalize_key_type_for_ui(&entry.key_type),
            key_b64: key_b64.clone(),
        }),
        keystore::KeyMaterial::RsaPrivate { private_pem, public_pem } => Ok(KeyPreview::Rsa {
            label: entry.label.clone(),
            material_kind: material_kind_for_entry(entry),
            public_pem: public_pem.clone(),
            private_pem: Some(private_pem.clone()),
        }),
        keystore::KeyMaterial::RsaPublic { public_pem } => Ok(KeyPreview::Rsa {
            label: entry.label.clone(),
            material_kind: material_kind_for_entry(entry),
            public_pem: Some(public_pem.clone()),
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
// 密钥详情：读取/编辑/手动导入
// =====================

/// 给前端“密钥详情弹窗”使用的结构：
/// - 需要包含敏感材料（用于展示/复制/编辑），因此只在后端读取并返回。
/// - 前端渲染时需要默认隐藏敏感字段，并对“显示/复制”做二次确认（由前端控制）。
#[derive(Debug, Serialize)]
pub struct KeyDetail {
    pub id: String,
    pub label: String,
    pub key_type: String,
    pub material_kind: String,

    pub symmetric_key_b64: Option<String>,

    pub rsa_public_pem: Option<String>,
    pub rsa_private_pem: Option<String>,

    pub x25519_public_b64: Option<String>,
    pub x25519_secret_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GetKeyDetailRequest {
    pub id: String,
}

#[tauri::command]
pub fn keystore_get_key_detail(app: AppHandle, state: State<'_, AppState>, req: GetKeyDetailRequest) -> Result<KeyDetail, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    let plain = load_plain_for_read(&app, &state)?;
    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到该密钥".to_string())?;

    let mut out = KeyDetail {
        id: entry.id.clone(),
        label: entry.label.clone(),
        key_type: normalize_key_type_for_ui(&entry.key_type),
        material_kind: material_kind_for_entry(entry),
        symmetric_key_b64: None,
        rsa_public_pem: None,
        rsa_private_pem: None,
        x25519_public_b64: None,
        x25519_secret_b64: None,
    };

    match &entry.material {
        keystore::KeyMaterial::Symmetric { key_b64 } => {
            out.symmetric_key_b64 = Some(key_b64.clone());
        }
        keystore::KeyMaterial::RsaPublic { public_pem } => {
            out.rsa_public_pem = Some(public_pem.clone());
        }
        keystore::KeyMaterial::RsaPrivate { private_pem, public_pem } => {
            out.rsa_private_pem = Some(private_pem.clone());
            out.rsa_public_pem = public_pem.clone();
        }
        keystore::KeyMaterial::X25519 { secret_b64, public_b64 } => {
            out.x25519_secret_b64 = secret_b64.clone();
            out.x25519_public_b64 = public_b64.clone();
        }
    }

    Ok(out)
}

/// 前端“手动导入/编辑保存”用的请求：
/// - 对称：symmetric_key_b64 必填
/// - RSA：rsa_public_pem / rsa_private_pem 至少一个
/// - X25519：x25519_public_b64 / x25519_secret_b64 至少一个
#[derive(Debug, Deserialize)]
pub struct UpsertKeyRequest {
    pub key_type: String,
    pub label: String,

    pub symmetric_key_b64: Option<String>,

    pub rsa_public_pem: Option<String>,
    pub rsa_private_pem: Option<String>,

    pub x25519_public_b64: Option<String>,
    pub x25519_secret_b64: Option<String>,
}

/// 根据 UI 输入构造一个 `KeyMaterial`，并做基础校验。
///
/// 注意：
/// - 这里遵循产品规则：
///   - RSA：允许“仅公钥/仅私钥/完整”。
///   - X25519：允许“仅公钥/仅私钥/完整”，但缺失任意一项时不允许加/解密（能力限制在 text_crypto 中统一检查）。
fn build_material_from_upsert(req: &UpsertKeyRequest) -> Result<(String, keystore::KeyMaterial), String> {
    let key_type_raw = req.key_type.trim();
    if key_type_raw.is_empty() {
        return Err("key_type 不能为空".to_string());
    }

    // 兼容旧值：RSA 视为 RSA2048
    let key_type = if key_type_raw == "RSA" { "RSA2048" } else { key_type_raw };

    match key_type {
        "AES-256" | "ChaCha20" => {
            let key_b64 = req
                .symmetric_key_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "请输入对称密钥（Base64）".to_string())?;

            let decoded = base64::engine::general_purpose::STANDARD
                .decode(key_b64.as_bytes())
                .map_err(|e| format!("Base64 解码失败：{e}"))?;
            if decoded.len() != 32 {
                return Err("对称密钥长度必须为 32 字节（Base64 解码后）".to_string());
            }
            let normalized_b64 = base64::engine::general_purpose::STANDARD.encode(decoded);

            Ok((key_type.to_string(), keystore::KeyMaterial::Symmetric { key_b64: normalized_b64 }))
        }
        "X25519" => {
            let secret_b64 = req
                .x25519_secret_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let public_b64 = req
                .x25519_public_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            if secret_b64.is_none() && public_b64.is_none() {
                return Err("X25519 至少需要填写公钥或私钥".to_string());
            }

            if let Some(s) = &secret_b64 {
                let secret = base64::engine::general_purpose::STANDARD
                    .decode(s.as_bytes())
                    .map_err(|e| format!("X25519 私钥 Base64 解码失败：{e}"))?;
                if secret.len() != 32 {
                    return Err("X25519 私钥必须为 32 字节（Base64 解码后）".to_string());
                }
            }
            if let Some(s) = &public_b64 {
                let public = base64::engine::general_purpose::STANDARD
                    .decode(s.as_bytes())
                    .map_err(|e| format!("X25519 公钥 Base64 解码失败：{e}"))?;
                if public.len() != 32 {
                    return Err("X25519 公钥必须为 32 字节（Base64 解码后）".to_string());
                }
            }

            // 若两者都填了，则校验一致性（不做自动推导/修正）。
            if let (Some(secret_s), Some(public_s)) = (&secret_b64, &public_b64) {
                let secret_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
                    .decode(secret_s.as_bytes())
                    .map_err(|e| format!("X25519 私钥 Base64 解码失败：{e}"))?
                    .as_slice()
                    .try_into()
                    .map_err(|_| "X25519 私钥长度错误".to_string())?;

                let public_expect = X25519PublicKey::from(&X25519StaticSecret::from(secret_bytes));
                let public_expect_b64 = base64::engine::general_purpose::STANDARD.encode(public_expect.as_bytes());
                if public_expect_b64.trim() != public_s.trim() {
                    return Err("X25519 公钥与私钥不匹配".to_string());
                }
            }

            Ok((
                "X25519".to_string(),
                keystore::KeyMaterial::X25519 {
                    secret_b64,
                    public_b64,
                },
            ))
        }
        "RSA2048" | "RSA4096" => {
            let bits_expected = if key_type == "RSA4096" { 4096 } else { 2048 };

            let private_in = req
                .rsa_private_pem
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let public_in = req
                .rsa_public_pem
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());

            if private_in.is_none() && public_in.is_none() {
                return Err("RSA 至少需要填写公钥或私钥".to_string());
            }

            // 仅公钥：直接解析并归一化。
            if private_in.is_none() {
                let pub_key = RsaPublicKey::from_public_key_pem(public_in.unwrap())
                    .map_err(|e| format!("RSA 公钥解析失败：{e}"))?;
                if pub_key.n().bits() as usize != bits_expected {
                    return Err(format!("RSA 密钥位数不匹配：期望 {bits_expected}，实际 {}", pub_key.n().bits()));
                }
                let public_pem = pub_key
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                    .to_string();
                return Ok((key_type.to_string(), keystore::KeyMaterial::RsaPublic { public_pem }));
            }

            // 有私钥：支持 PKCS8 / PKCS1，导出为 PKCS8 并按规则决定是否存公钥。
            let private_in = private_in.unwrap();
            let private_key = RsaPrivateKey::from_pkcs8_pem(private_in)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_in))
                .map_err(|e| format!("RSA 私钥解析失败：{e}"))?;

            if private_key.n().bits() as usize != bits_expected {
                return Err(format!(
                    "RSA 密钥位数不匹配：期望 {bits_expected}，实际 {}",
                    private_key.n().bits()
                ));
            }

            let private_pem = private_key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                .to_string();

            // 用户若填写了公钥：校验必须与私钥匹配。
            let public_pem = if let Some(public_in) = public_in {
                let pub_key = RsaPublicKey::from_public_key_pem(public_in)
                    .map_err(|e| format!("RSA 公钥解析失败：{e}"))?;
                if pub_key.n() != private_key.n() || pub_key.e() != private_key.e() {
                    return Err("RSA 公钥与私钥不匹配".to_string());
                }
                Some(
                    pub_key
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                        .to_string(),
                )
            } else {
                None
            };

            Ok((
                key_type.to_string(),
                keystore::KeyMaterial::RsaPrivate {
                    private_pem,
                    public_pem,
                },
            ))
        }
        _ => Err(format!("不支持的 key_type：{key_type}")),
    }
}

#[tauri::command]
pub fn keystore_import_key_manual(app: AppHandle, state: State<'_, AppState>, req: UpsertKeyRequest) -> Result<KeyEntryPublic, String> {
    let label = req.label.trim();
    if label.is_empty() {
        return Err("请输入密钥名称".to_string());
    }

    with_plain_mutation(&app, &state, |plain| {
        // 写操作前，顺手把旧数据里的 RSA 升级成 RSA2048，避免混用。
        normalize_key_type_in_place(plain);

        let (key_type, material) = build_material_from_upsert(&req)?;
        let id = keystore::generate_entry_id();

        plain.key_entries.push(keystore::KeyEntry {
            id: id.clone(),
            label: label.to_string(),
            key_type: key_type.clone(),
            material,
        });

        let last = plain
            .key_entries
            .last()
            .ok_or_else(|| "内部错误：导入后未找到条目".to_string())?;

        Ok(KeyEntryPublic {
            id,
            label: label.to_string(),
            key_type: normalize_key_type_for_ui(&key_type),
            material_kind: material_kind_for_entry(last),
        })
    })
}

#[derive(Debug, Deserialize)]
pub struct UpdateKeyRequest {
    pub id: String,
    #[serde(flatten)]
    pub data: UpsertKeyRequest,
}

#[tauri::command]
pub fn keystore_update_key(app: AppHandle, state: State<'_, AppState>, req: UpdateKeyRequest) -> Result<KeyEntryPublic, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }
    let label = req.data.label.trim();
    if label.is_empty() {
        return Err("请输入密钥名称".to_string());
    }

    with_plain_mutation(&app, &state, |plain| {
        // 写操作前，顺手把旧数据里的 RSA 升级成 RSA2048，避免混用。
        normalize_key_type_in_place(plain);

        let (key_type, material) = build_material_from_upsert(&req.data)?;

        let entry = plain
            .key_entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "未找到该密钥".to_string())?;

        entry.label = label.to_string();
        entry.key_type = key_type.clone();
        entry.material = material;

        Ok(KeyEntryPublic {
            id: entry.id.clone(),
            label: entry.label.clone(),
            key_type: normalize_key_type_for_ui(&entry.key_type),
            material_kind: material_kind_for_entry(entry),
        })
    })
}

// =====================
// 文本加密/解密（后端执行）
// =====================

/// 文本加密请求：前端只传“算法 + 密钥 + 明文”，加密全部在后端完成。
#[derive(Debug, Deserialize)]
pub struct TextEncryptRequest {
    /// 选择的算法：AES-256 / ChaCha20 / RSA2048 / RSA4096 / X25519
    ///
    /// 兼容：历史的 "RSA" 会被视为 "RSA2048"。
    pub algorithm: String,
    /// 密钥库条目 id
    pub key_id: String,
    /// 明文输入（UTF-8）
    pub plaintext: String,
}

/// 文本解密请求：前端只传“算法 + 密钥 + 密文(JSON)”，解密全部在后端完成。
#[derive(Debug, Deserialize)]
pub struct TextDecryptRequest {
    /// 选择的算法：AES-256 / ChaCha20 / RSA2048 / RSA4096 / X25519
    ///
    /// 兼容：历史的 "RSA" 会被视为 "RSA2048"。
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
