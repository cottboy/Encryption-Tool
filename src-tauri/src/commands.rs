/*
  Tauri 命令集合：
  - 原则：
    1) 前端只做 UI 与参数收集
    2) 密钥生成/导入/导出/持久化全部在 Rust 后端完成

  本阶段命令重点：
  - 单一密钥库（一个 keystore.json）
  - 支持密钥生成/导入/导出：AES-256 / ChaCha20 / RSA2048 / RSA4096 / X25519
  - 支持应用锁（密钥库加密）：启用后启动必须解锁
*/

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::{
    file_crypto, keystore,
    state::{AppState, FileCryptoTaskControl, UnlockedKeystore},
    text_crypto,
};

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

// =====================
// 算法声明（用于 UI 动态表单）
// =====================

/// 给前端的“算法字段声明”：前端可据此动态渲染“导入/编辑密钥”的输入框。
///
/// 说明：
/// - 这里输出的是“i18n key”，前端用 `$t(key)` 渲染成中文/英文等文案；
/// - 这样可以避免后端硬编码具体语言，同时保持“声明驱动 UI”。
#[derive(Debug, Clone, Serialize)]
pub struct AlgorithmKeyFieldSpec {
    /// 对应请求字段名（固定集合，例如 symmetric_key_b64 / rsa_public_pem 等）。
    pub field: &'static str,
    /// label 的翻译 key。
    pub label_key: &'static str,
    /// placeholder 的翻译 key（可选）。
    pub placeholder_key: Option<&'static str>,
    /// textarea 行数。
    pub rows: u8,
    /// 字段提示的翻译 key（可选）。
    pub hint_key: Option<&'static str>,
}

/// 给前端的“算法表单声明”。
#[derive(Debug, Clone, Serialize)]
pub struct AlgorithmFormSpec {
    pub id: &'static str,
    pub category: &'static str,
    pub encrypt_needs: &'static str,
    pub decrypt_needs: &'static str,
    pub key_fields: Vec<AlgorithmKeyFieldSpec>,
}

#[tauri::command]
pub fn get_algorithm_form_specs() -> Vec<AlgorithmFormSpec> {
    crate::crypto_algorithms::all_specs()
        .iter()
        .map(|spec| AlgorithmFormSpec {
            id: spec.id,
            category: match spec.category {
                crate::crypto_algorithms::AlgorithmCategory::Symmetric => "symmetric",
                crate::crypto_algorithms::AlgorithmCategory::Asymmetric => "asymmetric",
            },
            encrypt_needs: spec.encrypt_needs,
            decrypt_needs: spec.decrypt_needs,
            key_fields: spec
                .key_fields
                .iter()
                .map(|f| AlgorithmKeyFieldSpec {
                    field: f.field,
                    label_key: f.label_key,
                    placeholder_key: f.placeholder_key,
                    rows: f.rows,
                    hint_key: f.hint_key,
                })
                .collect(),
        })
        .collect()
}

#[tauri::command]
pub fn get_supported_algorithms() -> SupportedAlgorithms {
    // 单一来源：算法列表来自 crypto_algorithms 注册表，避免前后端/多模块分别维护。
    let mut symmetric = Vec::new();
    let mut asymmetric = Vec::new();

    for spec in crate::crypto_algorithms::all_specs() {
        match spec.category {
            crate::crypto_algorithms::AlgorithmCategory::Symmetric => symmetric.push(spec.id),
            crate::crypto_algorithms::AlgorithmCategory::Asymmetric => asymmetric.push(spec.id),
        }
    }

    SupportedAlgorithms {
        symmetric,
        asymmetric,
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

    /// 密钥类型（算法）：例如 AES-256 / ChaCha20 / RSA2048 / RSA4096 / X25519。
    pub key_type: String,

    /// 材料类型：用于前端决定“可预览/可导出”的具体格式。
    ///
    /// 需求变更：前端需要在列表中展示“仅公钥/仅私钥/完整”等状态，因此这里更细分：
    /// - symmetric
    /// - rsa_public_only / rsa_private_only / rsa_full
    /// - x25519_public_only / x25519_secret_only / x25519_full
    pub material_kind: String,
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
            if public_pem
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .is_some()
            {
                "rsa_full".to_string()
            } else {
                "rsa_private_only".to_string()
            }
        }
        keystore::KeyMaterial::X25519 {
            secret_b64,
            public_b64,
        } => {
            let has_secret = secret_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .is_some();
            let has_public = public_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .is_some();
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
pub fn keystore_status(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<keystore::KeyStoreStatus, String> {
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
pub fn keystore_unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;

    let (plain, derived) = keystore::decrypt_with_password_and_derived_key(&app, password.trim())
        .map_err(|e| e.to_string())?;

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

    match new_password
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(pw) => {
            // 启用/修改应用锁：用新密码加密并写回。
            let (file, kdf, key) =
                keystore::encrypt_with_new_password(&plain, pw).map_err(|e| e.to_string())?;
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
pub fn keystore_list_entries(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<KeyEntryPublic>, String> {
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

    let label = req.label.unwrap_or_default().trim().to_string();

    with_plain_mutation(&app, &state, |plain| {
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
                // 生成逻辑集中在 crypto_algorithms：避免命令层自己拼装细节，便于未来扩展算法/密钥类型。
                let (secret_b64, public_b64) =
                    crate::crypto_algorithms::generate_x25519_keypair_b64();

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
            "RSA2048" | "RSA4096" => {
                // RSA2048 / RSA4096 生成逻辑集中在 crypto_algorithms（两种算法分别一个文件）。
                let (private_pem, public_pem) =
                    crate::crypto_algorithms::generate_rsa_keypair_pem(key_type)?;

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: key_type.to_string(),
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
pub fn keystore_import_key(
    app: AppHandle,
    state: State<'_, AppState>,
    req: ImportKeyRequest,
) -> Result<KeyEntryPublic, String> {
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
                    (
                        j.secret_b64
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                        j.public_b64
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    )
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

                    let public_expect =
                        X25519PublicKey::from(&X25519StaticSecret::from(secret_bytes));
                    let public_expect_b64 =
                        base64::engine::general_purpose::STANDARD.encode(public_expect.as_bytes());

                    // 这里不做“自动修正”，而是提示用户输入不匹配，避免产生误解。
                    if public_expect_b64.trim() != public_s.trim() {
                        return Err("X25519 公钥与私钥不匹配".to_string());
                    }
                }

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: "X25519".to_string(),
                    material: keystore::KeyMaterial::X25519 {
                        secret_b64,
                        public_b64,
                    },
                }
            }
            "RSA2048" | "RSA4096" => {
                // RSA 导入（文件方式）：
                // - 兼容：既支持私钥 PEM，也支持公钥 PEM。
                // - 需求变更：允许“仅公钥/仅私钥”。为了可控，这里不自动从私钥推导公钥。
                let bits_expected = match key_type {
                    "RSA4096" => Some(4096),
                    "RSA2048" => Some(2048),
                    _ => None,
                };

                let trimmed = text.trim();

                // 先尝试 PKCS8 私钥。
                if let Ok(private) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
                    // 位数校验（可选）：避免用户把 2048 的材料导入成 RSA4096 之类的“挂羊头卖狗肉”。
                    if let Some(bits) = bits_expected {
                        if private.n().bits() as usize != bits {
                            return Err(format!(
                                "RSA 密钥位数不匹配：期望 {bits}，实际 {}",
                                private.n().bits()
                            ));
                        }
                    }
                    let private_pem = private
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: key_type.to_string(),
                        material: keystore::KeyMaterial::RsaPrivate {
                            private_pem,
                            public_pem: None,
                        },
                    }
                }
                // 再尝试 PKCS1 私钥（BEGIN RSA PRIVATE KEY）。
                else if let Ok(private) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
                    if let Some(bits) = bits_expected {
                        if private.n().bits() as usize != bits {
                            return Err(format!(
                                "RSA 密钥位数不匹配：期望 {bits}，实际 {}",
                                private.n().bits()
                            ));
                        }
                    }
                    let private_pem = private
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 私钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: key_type.to_string(),
                        material: keystore::KeyMaterial::RsaPrivate {
                            private_pem,
                            public_pem: None,
                        },
                    }
                }
                // 最后尝试公钥（BEGIN PUBLIC KEY）。
                else if let Ok(public) = RsaPublicKey::from_public_key_pem(trimmed) {
                    if let Some(bits) = bits_expected {
                        if public.n().bits() as usize != bits {
                            return Err(format!(
                                "RSA 密钥位数不匹配：期望 {bits}，实际 {}",
                                public.n().bits()
                            ));
                        }
                    }
                    let public_pem = public
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                        .to_string();

                    keystore::KeyEntry {
                        id: id.clone(),
                        label: entry_label.clone(),
                        key_type: key_type.to_string(),
                        material: keystore::KeyMaterial::RsaPublic { public_pem },
                    }
                } else {
                    return Err(
                        "无法识别 RSA 密钥格式（支持 PKCS8/PKCS1 私钥 PEM 或公钥 PEM）".to_string(),
                    );
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
            key_type: key_type.to_string(),
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
pub fn keystore_export_key(
    app: AppHandle,
    state: State<'_, AppState>,
    req: ExportKeyRequest,
) -> Result<(), String> {
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
        (
            "RSA2048" | "RSA4096",
            keystore::KeyMaterial::RsaPrivate { private_pem, .. },
            "private_pem",
        ) => private_pem.clone(),
        (
            "RSA2048" | "RSA4096",
            keystore::KeyMaterial::RsaPrivate { public_pem, .. },
            "public_pem",
        ) => public_pem
            .clone()
            .ok_or_else(|| "该 RSA 条目缺少公钥，无法导出公钥".to_string())?,
        ("RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPublic { public_pem }, "public_pem") => {
            public_pem.clone()
        }
        ("X25519", keystore::KeyMaterial::X25519 { public_b64, .. }, "public_b64") => public_b64
            .clone()
            .ok_or_else(|| "该 X25519 条目缺少公钥，无法导出公钥".to_string())?,
        (
            "X25519",
            keystore::KeyMaterial::X25519 {
                secret_b64,
                public_b64,
            },
            "json",
        ) => {
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
pub fn keystore_delete_key(
    app: AppHandle,
    state: State<'_, AppState>,
    req: DeleteKeyRequest,
) -> Result<(), String> {
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
fn load_plain_for_read(
    app: &AppHandle,
    state: &State<'_, AppState>,
) -> Result<keystore::KeyStorePlain, String> {
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
        }
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
) -> Result<
    (
        keystore::KeyStorePlain,
        Option<(keystore::KdfParams, Zeroizing<[u8; 32]>)>,
    ),
    String,
> {
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
            keystore::write_encrypted(app, &plain, &kdf, &derived_key)
                .map_err(|e| e.to_string())?;

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
fn write_file_atomic(
    path: &std::path::Path,
    file: &keystore::KeyStoreFile,
) -> Result<(), keystore::KeyStoreError> {
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
pub fn keystore_get_key_preview(
    app: AppHandle,
    state: State<'_, AppState>,
    req: GetKeyPreviewRequest,
) -> Result<KeyPreview, String> {
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
        keystore::KeyMaterial::RsaPrivate {
            private_pem,
            public_pem,
        } => Ok(KeyPreview::Rsa {
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
        keystore::KeyMaterial::X25519 {
            secret_b64,
            public_b64,
        } => Ok(KeyPreview::X25519 {
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
pub fn keystore_get_key_detail(
    app: AppHandle,
    state: State<'_, AppState>,
    req: GetKeyDetailRequest,
) -> Result<KeyDetail, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    let plain = load_plain_for_read(&app, &state)?;
    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到该密钥".to_string())?;

    let mut out = KeyDetail {
        id: entry.id.clone(),
        label: entry.label.clone(),
        key_type: entry.key_type.clone(),
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
        keystore::KeyMaterial::RsaPrivate {
            private_pem,
            public_pem,
        } => {
            out.rsa_private_pem = Some(private_pem.clone());
            out.rsa_public_pem = public_pem.clone();
        }
        keystore::KeyMaterial::X25519 {
            secret_b64,
            public_b64,
        } => {
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
fn build_material_from_upsert(
    req: &UpsertKeyRequest,
) -> Result<(String, keystore::KeyMaterial), String> {
    let key_type_raw = req.key_type.trim();
    if key_type_raw.is_empty() {
        return Err("key_type 不能为空".to_string());
    }
    let key_type = key_type_raw;

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

            Ok((
                key_type.to_string(),
                keystore::KeyMaterial::Symmetric {
                    key_b64: normalized_b64,
                },
            ))
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
                let public_expect_b64 =
                    base64::engine::general_purpose::STANDARD.encode(public_expect.as_bytes());
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
                    return Err(format!(
                        "RSA 密钥位数不匹配：期望 {bits_expected}，实际 {}",
                        pub_key.n().bits()
                    ));
                }
                let public_pem = pub_key
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| format!("RSA 公钥导出失败：{e}"))?
                    .to_string();
                return Ok((
                    key_type.to_string(),
                    keystore::KeyMaterial::RsaPublic { public_pem },
                ));
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
pub fn keystore_import_key_manual(
    app: AppHandle,
    state: State<'_, AppState>,
    req: UpsertKeyRequest,
) -> Result<KeyEntryPublic, String> {
    let label = req.label.trim();
    if label.is_empty() {
        return Err("请输入密钥名称".to_string());
    }

    with_plain_mutation(&app, &state, |plain| {
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
            key_type,
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
pub fn keystore_update_key(
    app: AppHandle,
    state: State<'_, AppState>,
    req: UpdateKeyRequest,
) -> Result<KeyEntryPublic, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }
    let label = req.data.label.trim();
    if label.is_empty() {
        return Err("请输入密钥名称".to_string());
    }

    with_plain_mutation(&app, &state, |plain| {
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
            key_type: entry.key_type.clone(),
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
    pub algorithm: String,
    /// 密钥库条目 id
    pub key_id: String,
    /// 密文输入（JSON 自描述容器）
    pub ciphertext: String,
}

/// 文本加密：返回 JSON 密文与“是否混合加密”提示位。
#[tauri::command]
pub fn text_encrypt(
    app: AppHandle,
    state: State<'_, AppState>,
    req: TextEncryptRequest,
) -> Result<text_crypto::TextEncryptResponse, String> {
    // 读取密钥库明文：若密钥库已加密但未解锁，这里会返回“需要输入密码解锁”。
    let plain = load_plain_for_read(&app, &state)?;

    // 调用专用模块执行加密：避免 commands.rs 继续膨胀。
    text_crypto::encrypt_text(&plain, &req.algorithm, &req.key_id, &req.plaintext)
}

/// 文本解密：返回明文；解密失败统一提示“密钥错误或数据已损坏”。
#[tauri::command]
pub fn text_decrypt(
    app: AppHandle,
    state: State<'_, AppState>,
    req: TextDecryptRequest,
) -> Result<text_crypto::TextDecryptResponse, String> {
    // 读取密钥库明文：若密钥库已加密但未解锁，这里会返回“需要输入密码解锁”。
    let plain = load_plain_for_read(&app, &state)?;

    // 调用专用模块执行解密：内部已做错误收敛处理。
    text_crypto::decrypt_text(&plain, &req.algorithm, &req.key_id, &req.ciphertext)
}

// =====================
// 文件加密/解密（后端执行，流式分块）
// =====================

/// 文件加密/解密的进度事件名：前端通过 `listen` 订阅。
const EVENT_FILE_CRYPTO_PROGRESS: &str = "file_crypto_progress";
/// 文件加密/解密的完成事件名：前端通过 `listen` 订阅。
const EVENT_FILE_CRYPTO_DONE: &str = "file_crypto_done";
/// 文件加密/解密的错误事件名：前端通过 `listen` 订阅。
const EVENT_FILE_CRYPTO_ERROR: &str = "file_crypto_error";
/// 文件加密/解密的取消事件名：前端通过 `listen` 订阅。
const EVENT_FILE_CRYPTO_CANCELED: &str = "file_crypto_canceled";

/// 文件加密/解密：进度事件负载。
#[derive(Debug, Clone, Serialize)]
pub struct FileCryptoProgressEvent {
    /// 任务 id：用于前端只更新“当前任务”的进度。
    pub task_id: String,
    /// 阶段：encrypt / decrypt（便于 UI 区分提示文案）。
    pub stage: String,
    /// 已处理字节数（明文维度）。
    pub processed_bytes: u64,
    /// 总字节数（明文维度）。
    pub total_bytes: u64,
}

/// 文件加密/解密：完成事件负载。
#[derive(Debug, Clone, Serialize)]
pub struct FileCryptoDoneEvent {
    pub task_id: String,
    pub output_path: String,
}

/// 文件加密/解密：错误事件负载。
#[derive(Debug, Clone, Serialize)]
pub struct FileCryptoErrorEvent {
    pub task_id: String,
    pub message: String,
}

/// 文件加密/解密：取消事件负载。
#[derive(Debug, Clone, Serialize)]
pub struct FileCryptoCanceledEvent {
    pub task_id: String,
}

/// 文件加密请求：
/// - 前端传入算法 + 密钥 id + 输入文件路径 + 输出目录（可选）。
#[derive(Debug, Deserialize)]
pub struct FileEncryptRequest {
    pub algorithm: String,
    pub key_id: String,
    pub input_path: String,
    pub output_dir: Option<String>,
}

/// 文件解密请求：
/// - 前端传入算法 + 密钥 id + 输入 `.encrypted` 文件路径 + 输出目录（可选）。
#[derive(Debug, Deserialize)]
pub struct FileDecryptRequest {
    pub algorithm: String,
    pub key_id: String,
    pub input_path: String,
    pub output_dir: Option<String>,
}

/// 文件任务开始返回：
/// - task_id：用于前端订阅进度与取消
/// - output_path：后端推导出的输出路径（便于 UI 展示）
/// - original_file_name：仅解密场景返回（用于 UI 展示“将还原为 XXX”）
#[derive(Debug, Serialize)]
pub struct FileCryptoStartResponse {
    pub task_id: String,
    pub output_path: String,
    pub original_file_name: Option<String>,
}

/// 解析并规范化输出目录：
/// - 为空则回退到 `default_dir`
/// - 非目录则返回错误
fn normalize_output_dir(input: &Option<String>, default_dir: &Path) -> Result<PathBuf, String> {
    let dir = match input.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => default_dir.to_path_buf(),
    };

    if !dir.exists() {
        return Err("输出目录不存在".to_string());
    }
    if !dir.is_dir() {
        return Err("输出目录不是文件夹".to_string());
    }
    Ok(dir)
}

/// 从 keystore 中解析“文件加密侧”密钥材料：
/// - 对称：需要 32 字节 key
/// - RSA：需要公钥 PEM（RsaPublic 或 RsaPrivate 中携带的 public_pem）
/// - X25519：产品规则要求“完整”（公钥+私钥），但加密时实际只使用公钥
fn resolve_file_encrypt_key(
    plain: &keystore::KeyStorePlain,
    algorithm: &str,
    key_id: &str,
) -> Result<file_crypto::EncryptKeyMaterial, String> {
    let entry =
        keystore::find_entry(plain, key_id).ok_or_else(|| "未找到指定的密钥".to_string())?;

    if entry.key_type != algorithm {
        return Err("所选密钥与算法不匹配".to_string());
    }

    match (&entry.key_type[..], &entry.material) {
        ("AES-256" | "ChaCha20", keystore::KeyMaterial::Symmetric { key_b64 }) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(key_b64.trim())
                .map_err(|_| "对称密钥 Base64 解码失败".to_string())?;
            if bytes.len() != 32 {
                return Err("对称密钥必须为 32 字节".to_string());
            }
            let mut key_32 = Zeroizing::new([0u8; 32]);
            key_32.copy_from_slice(&bytes);

            Ok(file_crypto::EncryptKeyMaterial::Symmetric {
                alg: entry.key_type.clone(),
                key_32,
            })
        }
        ("RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPublic { public_pem }) => {
            Ok(file_crypto::EncryptKeyMaterial::RsaPublic {
                alg: entry.key_type.clone(),
                public_pem: public_pem.clone(),
            })
        }
        ("RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPrivate { public_pem, .. }) => {
            let pub_pem = public_pem
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "RSA 加密需要公钥，请选择包含公钥的 RSA 密钥".to_string())?;

            Ok(file_crypto::EncryptKeyMaterial::RsaPublic {
                alg: entry.key_type.clone(),
                public_pem: pub_pem.to_string(),
            })
        }
        (
            "X25519",
            keystore::KeyMaterial::X25519 {
                secret_b64,
                public_b64,
            },
        ) => {
            // 产品规则：X25519 必须同时拥有公钥+私钥才允许加/解密。
            let pub_b64 = public_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "X25519 加密需要公钥，请选择“完整”类型的 X25519 密钥".to_string())?;
            let sec_b64 = secret_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "X25519 加密/解密需要私钥，请选择“完整”类型的 X25519 密钥".to_string()
                })?;

            // 公钥解析（32 字节）
            let pub_bytes = base64::engine::general_purpose::STANDARD
                .decode(pub_b64)
                .map_err(|_| "X25519 公钥 Base64 解码失败".to_string())?;
            if pub_bytes.len() != 32 {
                return Err("X25519 公钥必须为 32 字节".to_string());
            }
            let mut pub_32 = [0u8; 32];
            pub_32.copy_from_slice(&pub_bytes);

            // 私钥仅用于“规则校验”（确保完整）；实际加密流程只需要公钥。
            let sec_bytes = base64::engine::general_purpose::STANDARD
                .decode(sec_b64)
                .map_err(|_| "X25519 私钥 Base64 解码失败".to_string())?;
            if sec_bytes.len() != 32 {
                return Err("X25519 私钥必须为 32 字节".to_string());
            }

            Ok(file_crypto::EncryptKeyMaterial::X25519Public { public_32: pub_32 })
        }
        _ => Err("所选密钥类型不支持当前算法".to_string()),
    }
}

/// 从 keystore 中解析“文件解密侧”密钥材料：
/// - 对称：需要 32 字节 key
/// - RSA：需要私钥 PEM
/// - X25519：产品规则要求“完整”（公钥+私钥），但解密时实际只使用私钥
fn resolve_file_decrypt_key(
    plain: &keystore::KeyStorePlain,
    algorithm: &str,
    key_id: &str,
) -> Result<file_crypto::DecryptKeyMaterial, String> {
    let entry =
        keystore::find_entry(plain, key_id).ok_or_else(|| "未找到指定的密钥".to_string())?;

    if entry.key_type != algorithm {
        return Err("所选密钥与算法不匹配".to_string());
    }

    match (&entry.key_type[..], &entry.material) {
        ("AES-256" | "ChaCha20", keystore::KeyMaterial::Symmetric { key_b64 }) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(key_b64.trim())
                .map_err(|_| "对称密钥 Base64 解码失败".to_string())?;
            if bytes.len() != 32 {
                return Err("对称密钥必须为 32 字节".to_string());
            }
            let mut key_32 = Zeroizing::new([0u8; 32]);
            key_32.copy_from_slice(&bytes);

            Ok(file_crypto::DecryptKeyMaterial::Symmetric {
                alg: entry.key_type.clone(),
                key_32,
            })
        }
        ("RSA2048" | "RSA4096", keystore::KeyMaterial::RsaPrivate { private_pem, .. }) => {
            Ok(file_crypto::DecryptKeyMaterial::RsaPrivate {
                private_pem: private_pem.clone(),
            })
        }
        ("RSA2048" | "RSA4096", _) => {
            Err("RSA 解密需要私钥，请选择包含私钥的 RSA 密钥".to_string())
        }
        (
            "X25519",
            keystore::KeyMaterial::X25519 {
                secret_b64,
                public_b64,
            },
        ) => {
            // 产品规则：X25519 必须同时拥有公钥+私钥才允许加/解密。
            let _pub_b64 = public_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "X25519 解密需要公钥+私钥，请选择“完整”类型的 X25519 密钥".to_string()
                })?;
            let sec_b64 = secret_b64
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "X25519 解密需要私钥，请选择“完整”类型的 X25519 密钥".to_string())?;

            let sec_bytes = base64::engine::general_purpose::STANDARD
                .decode(sec_b64)
                .map_err(|_| "X25519 私钥 Base64 解码失败".to_string())?;
            if sec_bytes.len() != 32 {
                return Err("X25519 私钥必须为 32 字节".to_string());
            }
            let mut sec_32 = Zeroizing::new([0u8; 32]);
            sec_32.copy_from_slice(&sec_bytes);

            Ok(file_crypto::DecryptKeyMaterial::X25519Secret { secret_32: sec_32 })
        }
        _ => Err("所选密钥类型不支持当前算法".to_string()),
    }
}

/// 启动文件加密任务（后台线程执行，前端通过事件拿进度）。
#[tauri::command]
pub fn file_encrypt_start(
    app: AppHandle,
    state: State<'_, AppState>,
    req: FileEncryptRequest,
) -> Result<FileCryptoStartResponse, String> {
    // 读取密钥库明文：若密钥库已加密但未解锁，这里会返回“需要输入密码解锁”。
    let plain = load_plain_for_read(&app, &state)?;

    let algo = req.algorithm.trim();
    if algo.is_empty() {
        return Err("请选择算法".to_string());
    }
    let key_id = req.key_id.trim();
    if key_id.is_empty() {
        return Err("请选择密钥".to_string());
    }

    let input_path = PathBuf::from(req.input_path.trim());
    if req.input_path.trim().is_empty() {
        return Err("请选择输入文件".to_string());
    }

    let default_dir = input_path
        .parent()
        .ok_or_else(|| "无法解析输入文件所在目录".to_string())?;

    let output_dir = normalize_output_dir(&req.output_dir, default_dir)?;
    let output_path = file_crypto::build_encrypt_output_path(&input_path, &output_dir)?;

    // 解析密钥材料：提前做参数校验，避免任务启动后才失败。
    let key = resolve_file_encrypt_key(&plain, algo, key_id)?;

    // 生成任务 id，并在 AppState 中注册取消标记。
    let task_id = keystore::generate_entry_id();
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut guard = state
            .file_crypto_tasks
            .lock()
            .map_err(|_| "内部错误：任务状态锁被占用".to_string())?;
        guard.insert(
            task_id.clone(),
            FileCryptoTaskControl {
                cancel: cancel.clone(),
            },
        );
    }

    // 后台线程执行：避免阻塞 Tauri 命令调用线程。
    let app2 = app.clone();
    let task_id2 = task_id.clone();
    let output_path2 = output_path.clone();
    std::thread::spawn(move || {
        // 进度回调：每次分块都会回调一次，前端据此更新进度条。
        let emit_progress = |processed: u64, total: u64| {
            let _ = app2.emit(
                EVENT_FILE_CRYPTO_PROGRESS,
                FileCryptoProgressEvent {
                    task_id: task_id2.clone(),
                    stage: "encrypt".to_string(),
                    processed_bytes: processed,
                    total_bytes: total,
                },
            );
        };

        let is_canceled = || cancel.load(Ordering::Relaxed);

        let res = file_crypto::encrypt_file_stream(
            &input_path,
            &output_path2,
            key,
            &emit_progress,
            &is_canceled,
        );

        match res {
            Ok(file_crypto::FileCryptoOutcome::Completed) => {
                let _ = app2.emit(
                    EVENT_FILE_CRYPTO_DONE,
                    FileCryptoDoneEvent {
                        task_id: task_id2.clone(),
                        output_path: output_path2.to_string_lossy().to_string(),
                    },
                );
            }
            Ok(file_crypto::FileCryptoOutcome::Canceled) => {
                let _ = app2.emit(
                    EVENT_FILE_CRYPTO_CANCELED,
                    FileCryptoCanceledEvent {
                        task_id: task_id2.clone(),
                    },
                );
            }
            Err(e) => {
                let _ = app2.emit(
                    EVENT_FILE_CRYPTO_ERROR,
                    FileCryptoErrorEvent {
                        task_id: task_id2.clone(),
                        message: e,
                    },
                );
            }
        }

        // 无论成功/失败/取消，都要清理任务状态，避免内存泄漏。
        // 注意：显式用一个作用域包住 lock，避免出现“临时值析构晚于借用”的生命周期报错。
        {
            let s = app2.state::<AppState>();
            if let Ok(mut guard) = s.file_crypto_tasks.lock() {
                guard.remove(&task_id2);
            };
        }
    });

    Ok(FileCryptoStartResponse {
        task_id,
        output_path: output_path.to_string_lossy().to_string(),
        original_file_name: None,
    })
}

/// 启动文件解密任务（后台线程执行，前端通过事件拿进度）。
#[tauri::command]
pub fn file_decrypt_start(
    app: AppHandle,
    state: State<'_, AppState>,
    req: FileDecryptRequest,
) -> Result<FileCryptoStartResponse, String> {
    // 读取密钥库明文：若密钥库已加密但未解锁，这里会返回“需要输入密码解锁”。
    let plain = load_plain_for_read(&app, &state)?;

    // 注意：后续要把算法传入后台线程，因此这里先转成 owned String，避免引用跨线程导致生命周期问题。
    let algo = req.algorithm.trim().to_string();
    if algo.is_empty() {
        return Err("请选择算法".to_string());
    }
    let key_id = req.key_id.trim();
    if key_id.is_empty() {
        return Err("请选择密钥".to_string());
    }

    let encrypted_path = PathBuf::from(req.input_path.trim());
    if req.input_path.trim().is_empty() {
        return Err("请选择输入文件".to_string());
    }

    let default_dir = encrypted_path
        .parent()
        .ok_or_else(|| "无法解析输入文件所在目录".to_string())?;

    let output_dir = normalize_output_dir(&req.output_dir, default_dir)?;

    // 先读取 header，用于：
    // 1) 校验用户选择的算法是否匹配文件
    // 2) 推导解密输出文件名（还原原始文件名）
    let header = file_crypto::read_header_only(&encrypted_path)?;
    let output_path = file_crypto::build_decrypt_output_path(&header, &output_dir)?;

    // 解析密钥材料：提前做参数校验，避免任务启动后才失败。
    let key = resolve_file_decrypt_key(&plain, &algo, key_id)?;

    // 生成任务 id，并在 AppState 中注册取消标记。
    let task_id = keystore::generate_entry_id();
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut guard = state
            .file_crypto_tasks
            .lock()
            .map_err(|_| "内部错误：任务状态锁被占用".to_string())?;
        guard.insert(
            task_id.clone(),
            FileCryptoTaskControl {
                cancel: cancel.clone(),
            },
        );
    }

    let app2 = app.clone();
    let task_id2 = task_id.clone();
    let output_path2 = output_path.clone();
    let algo2 = algo.clone();
    std::thread::spawn(move || {
        let emit_progress = |processed: u64, total: u64| {
            let _ = app2.emit(
                EVENT_FILE_CRYPTO_PROGRESS,
                FileCryptoProgressEvent {
                    task_id: task_id2.clone(),
                    stage: "decrypt".to_string(),
                    processed_bytes: processed,
                    total_bytes: total,
                },
            );
        };

        let is_canceled = || cancel.load(Ordering::Relaxed);

        let res = file_crypto::decrypt_file_stream(
            &encrypted_path,
            &output_path2,
            key,
            &algo2,
            &emit_progress,
            &is_canceled,
        );

        match res {
            Ok(file_crypto::FileCryptoOutcome::Completed) => {
                let _ = app2.emit(
                    EVENT_FILE_CRYPTO_DONE,
                    FileCryptoDoneEvent {
                        task_id: task_id2.clone(),
                        output_path: output_path2.to_string_lossy().to_string(),
                    },
                );
            }
            Ok(file_crypto::FileCryptoOutcome::Canceled) => {
                let _ = app2.emit(
                    EVENT_FILE_CRYPTO_CANCELED,
                    FileCryptoCanceledEvent {
                        task_id: task_id2.clone(),
                    },
                );
            }
            Err(e) => {
                let _ = app2.emit(
                    EVENT_FILE_CRYPTO_ERROR,
                    FileCryptoErrorEvent {
                        task_id: task_id2.clone(),
                        message: e,
                    },
                );
            }
        }

        {
            let s = app2.state::<AppState>();
            if let Ok(mut guard) = s.file_crypto_tasks.lock() {
                guard.remove(&task_id2);
            };
        }
    });

    Ok(FileCryptoStartResponse {
        task_id,
        output_path: output_path.to_string_lossy().to_string(),
        // 防护：header 来自外部输入文件，original_file_name 可能被篡改成带路径的字符串。
        // 这里返回“净化后的文件名”，保证：
        // - UI 展示的“将还原为 XXX”与实际输出路径一致；
        // - 避免在 UI 中出现迷惑性/攻击性路径文本（例如 `..\\..\\...`）。
        original_file_name: Some(file_crypto::sanitize_decrypt_output_file_name(&header)),
    })
}

/// 取消文件加密/解密任务：
/// - 前端调用后，仅设置 cancel 标记；实际停止发生在后台任务的分块循环内。
#[tauri::command]
pub fn file_crypto_cancel(state: State<'_, AppState>, task_id: String) -> Result<(), String> {
    let id = task_id.trim();
    if id.is_empty() {
        return Err("task_id 不能为空".to_string());
    }

    let guard = state
        .file_crypto_tasks
        .lock()
        .map_err(|_| "内部错误：任务状态锁被占用".to_string())?;

    let ctrl = guard.get(id).ok_or_else(|| "未找到该任务".to_string())?;
    ctrl.cancel.store(true, Ordering::Relaxed);
    Ok(())
}
