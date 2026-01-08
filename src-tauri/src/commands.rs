/*
  Tauri 命令集合：
  - 原则：
    1) 前端只做 UI 与参数收集
    2) 密钥生成/导入/导出/持久化全部在 Rust 后端完成

  本阶段命令重点：
  - 单一密钥库（一个 keystore.json）
  - 支持密钥生成/导入/导出：AES-256 / ChaCha20 / RSA-4096 / X25519 / ML-KEM-768
  - 说明：本项目已移除“应用锁/密钥库加密”，密钥库仅以明文 JSON 存储
*/

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::{
    file_crypto, keystore,
    state::{AppState, FileCryptoTaskControl},
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

/// 给前端的“算法 part 声明”：前端可据此动态渲染“导入/编辑密钥”的输入框。
///
/// 说明：
/// - 这里输出的是“i18n key”，前端用 `$t(key)` 渲染成中文/英文等文案；
/// - 这样可以避免后端硬编码具体语言，同时保持“声明驱动 UI”。
#[derive(Debug, Clone, Serialize)]
pub struct AlgorithmKeyPartSpec {
    /// part id：用于前端表单绑定与后端存储（例如 rsa_public_pem）。
    pub id: &'static str,
    /// part encoding：用于前端提示与后端解析（base64/pem/hex/utf8）。
    pub encoding: keystore::KeyPartEncoding,
    /// 是否为隐藏字段：前端不渲染输入框，但仍参与 required 判定与持久化。
    pub hidden: bool,
    /// label 的翻译 key。
    pub label_key: &'static str,
    /// placeholder 的翻译 key（可选）。
    pub placeholder_key: Option<&'static str>,
    /// textarea 行数。
    pub rows: u8,
    /// 字段提示的翻译 key（可选）。
    pub hint_key: Option<&'static str>,
    /// 是否为“加密必需”的 part（用于前端禁用/启用按钮）。
    pub required_for_encrypt: bool,
    /// 是否为“解密必需”的 part（用于前端禁用/启用按钮）。
    pub required_for_decrypt: bool,
}

/// 给前端的“算法表单声明”。
#[derive(Debug, Clone, Serialize)]
pub struct AlgorithmFormSpec {
    pub id: &'static str,
    pub category: &'static str,
    pub encrypt_needs_key: &'static str,
    pub decrypt_needs_key: &'static str,
    pub key_parts: Vec<AlgorithmKeyPartSpec>,
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
            encrypt_needs_key: spec.encrypt_needs_key,
            decrypt_needs_key: spec.decrypt_needs_key,
            key_parts: spec
                .key_parts
                .iter()
                .map(|p| AlgorithmKeyPartSpec {
                    id: p.id,
                    encoding: p.encoding,
                    hidden: p.hidden,
                    label_key: p.label_key,
                    placeholder_key: p.placeholder_key,
                    rows: p.rows,
                    hint_key: p.hint_key,
                    required_for_encrypt: p.required_for_encrypt,
                    required_for_decrypt: p.required_for_decrypt,
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
// 密钥库（KeyStore）
// =====================

/// 给前端展示的密钥条目（不包含敏感材料）。
#[derive(Debug, Serialize)]
pub struct KeyEntryPublic {
    /// 条目 ID：仅用于前后端交互与定位；UI 不展示。
    pub id: String,

    /// 用户可读名称：导入/生成时由用户设置。
    pub label: String,

    /// 密钥类型（算法）：例如 AES-256 / ChaCha20 / RSA-4096 / X25519 / ML-KEM-768。
    pub key_type: String,

    /// 当前条目包含哪些 parts（只返回 id，不返回 value）。
    ///
    /// 用途：
    /// - 前端基于“算法声明的 required parts + parts_present”判断该密钥能否用于加密/解密；
    /// - 同时可用于 UI 展示“仅公钥/仅私钥/完整”等状态（由前端按算法规则计算）。
    pub parts_present: Vec<String>,
}
/// 获取密钥库状态：
/// - 若首次启动没有密钥库文件，会自动创建一个明文空库。
#[tauri::command]
pub fn keystore_status(app: AppHandle) -> Result<keystore::KeyStoreStatus, String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;
    keystore::status(&app).map_err(|e| e.to_string())
}

/// 列出密钥条目（不包含敏感材料）。
/// - 未加密：直接读取文件
/// - 已加密：必须先解锁（从 state 读取）
#[tauri::command]
pub fn keystore_list_entries(app: AppHandle) -> Result<Vec<KeyEntryPublic>, String> {
    keystore::ensure_exists(&app).map_err(|e| e.to_string())?;
    let plain = keystore::read_plain(&app).map_err(|e| e.to_string())?;

    let entries = plain
        .key_entries
        .iter()
        .map(|e| {
            // 只返回“有哪些 part”，不返回具体 value，避免在列表接口泄露敏感材料。
            let parts_present = e
                .parts
                .iter()
                .filter(|p| !p.value.trim().is_empty())
                .map(|p| p.id.clone())
                .collect::<Vec<_>>();

            KeyEntryPublic {
                id: e.id.clone(),
                label: e.label.clone(),
                key_type: e.key_type.clone(),
                parts_present,
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
    req: GenerateKeyRequest,
) -> Result<KeyEntryPublic, String> {
    let key_type = req.key_type.trim();
    if key_type.is_empty() {
        return Err("key_type 不能为空".to_string());
    }

    let label = req.label.unwrap_or_default().trim().to_string();

    with_plain_mutation(&app, |plain| {
        let id = keystore::generate_entry_id();

        let entry_label = if label.is_empty() {
            format!("{key_type} 密钥")
        } else {
            label
        };

        // 生成密钥：
        // - 对称：随机 32 字节
        // - X25519：随机 32 字节私钥 + 对应公钥
        // - RSA：生成 4096 位密钥对
        let entry = match key_type {
            "AES-256" | "ChaCha20" => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: key_type.to_string(),
                    parts: vec![keystore::KeyPart {
                        id: "symmetric_key_b64".to_string(),
                        encoding: keystore::KeyPartEncoding::Base64,
                        value: key_b64,
                    }],
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
                    parts: vec![
                        keystore::KeyPart {
                            id: "x25519_secret_b64".to_string(),
                            encoding: keystore::KeyPartEncoding::Base64,
                            value: secret_b64,
                        },
                        keystore::KeyPart {
                            id: "x25519_public_b64".to_string(),
                            encoding: keystore::KeyPartEncoding::Base64,
                            value: public_b64,
                        },
                    ],
                }
            }
            "ML-KEM-768" => {
                // ML-KEM-768：生成密钥对（私钥 + 公钥）。
                // 会话共享密钥 ss 由后续“封装/解封”动作写入（不在前端展示）。
                let (secret_b64, public_b64) =
                    crate::crypto_algorithms::generate_mlkem768_keypair_b64();

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: "ML-KEM-768".to_string(),
                    parts: vec![
                        keystore::KeyPart {
                            id: "mlkem768_public_b64".to_string(),
                            encoding: keystore::KeyPartEncoding::Base64,
                            value: public_b64,
                        },
                        keystore::KeyPart {
                            id: "mlkem768_secret_b64".to_string(),
                            encoding: keystore::KeyPartEncoding::Base64,
                            value: secret_b64,
                        },
                    ],
                }
            }
            "RSA-4096" => {
                // RSA-4096 生成逻辑集中在 crypto_algorithms（算法文件负责生成与规范化）。
                let (private_pem, public_pem) =
                    crate::crypto_algorithms::generate_rsa_keypair_pem(key_type)?;

                keystore::KeyEntry {
                    id: id.clone(),
                    label: entry_label.clone(),
                    key_type: key_type.to_string(),
                    parts: vec![
                        keystore::KeyPart {
                            id: "rsa_private_pem".to_string(),
                            encoding: keystore::KeyPartEncoding::Pem,
                            value: private_pem,
                        },
                        keystore::KeyPart {
                            id: "rsa_public_pem".to_string(),
                            encoding: keystore::KeyPartEncoding::Pem,
                            value: public_pem,
                        },
                    ],
                }
            }
            _ => return Err(format!("不支持的 key_type：{key_type}")),
        };

        plain.key_entries.push(entry);

        // 返回给前端的“公共信息”，不包含任何敏感材料。
        let last = plain
            .key_entries
            .last()
            .ok_or_else(|| "内部错误：生成后未找到条目".to_string())?;
        let parts_present = last
            .parts
            .iter()
            .filter(|p| !p.value.trim().is_empty())
            .map(|p| p.id.clone())
            .collect::<Vec<_>>();

        Ok(KeyEntryPublic {
            id,
            label: entry_label.clone(),
            key_type: key_type.to_string(),
            parts_present,
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

    with_plain_mutation(&app, |plain| {
        let id = keystore::generate_entry_id();

        let entry_label = if label.is_empty() {
            format!("{key_type} 导入")
        } else {
            label
        };

        let parts_raw: Vec<keystore::KeyPart> = match key_type {
            "AES-256" | "ChaCha20" => {
                // 文件导入：将整个文件内容当作“对称密钥 Base64 文本”。
                // 具体 Base64 解码与长度校验由算法模块完成（normalize_parts_for_upsert）。
                vec![keystore::KeyPart {
                    id: "symmetric_key_b64".to_string(),
                    encoding: keystore::KeyPartEncoding::Base64,
                    value: text.trim().to_string(),
                }]
            }
            "X25519" => {
                // 优先尝试 JSON（我们自己的导出格式）。
                // 允许只导入公钥或只导入私钥（产品规则保持不变）。
                #[derive(Deserialize)]
                struct X25519Json {
                    secret_b64: Option<String>,
                    public_b64: Option<String>,
                }

                let trimmed = text.trim();
                let maybe_json: Result<X25519Json, _> = serde_json::from_str(trimmed);

                // 如果不是 JSON，则将其视为“Base64 编码的私钥”。
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

                // 文件导入只做“字段识别”，不在这里做长度/一致性校验；
                // 校验与规范化交给算法模块（normalize_parts_for_upsert）。
                let mut out = Vec::new();
                if let Some(v) = public_b64 {
                    out.push(keystore::KeyPart {
                        id: "x25519_public_b64".to_string(),
                        encoding: keystore::KeyPartEncoding::Base64,
                        value: v,
                    });
                }
                if let Some(v) = secret_b64 {
                    out.push(keystore::KeyPart {
                        id: "x25519_secret_b64".to_string(),
                        encoding: keystore::KeyPartEncoding::Base64,
                        value: v,
                    });
                }
                out
            }
            "RSA-4096" => {
                // 文件导入：这里只做“公钥/私钥”分类，不在这里解析/校验位数；
                // 具体解析、位数校验、PEM 规范化交给算法模块（normalize_parts_for_upsert）。
                let trimmed = text.trim();

                if trimmed.contains("BEGIN PRIVATE KEY")
                    || trimmed.contains("BEGIN RSA PRIVATE KEY")
                {
                    vec![keystore::KeyPart {
                        id: "rsa_private_pem".to_string(),
                        encoding: keystore::KeyPartEncoding::Pem,
                        value: trimmed.to_string(),
                    }]
                } else if trimmed.contains("BEGIN PUBLIC KEY") {
                    vec![keystore::KeyPart {
                        id: "rsa_public_pem".to_string(),
                        encoding: keystore::KeyPartEncoding::Pem,
                        value: trimmed.to_string(),
                    }]
                } else {
                    return Err(
                        "无法识别 RSA 密钥格式（支持 PEM：BEGIN PRIVATE KEY / BEGIN RSA PRIVATE KEY / BEGIN PUBLIC KEY）".to_string(),
                    );
                }
            }
            _ => return Err(format!("不支持的 key_type：{key_type}")),
        };

        // 算法级校验/规范化：确保 bits/长度/一致性等规则由算法文件统一处理。
        let parts = normalize_parts_for_upsert(key_type, parts_raw)?;

        let entry = keystore::KeyEntry {
            id: id.clone(),
            label: entry_label.clone(),
            key_type: key_type.to_string(),
            parts: parts.clone(),
        };

        plain.key_entries.push(entry);

        Ok(KeyEntryPublic {
            id,
            label: entry_label.clone(),
            key_type: key_type.to_string(),
            parts_present: parts.iter().map(|p| p.id.clone()).collect(),
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
pub fn keystore_export_key(app: AppHandle, req: ExportKeyRequest) -> Result<(), String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }
    let path = req.path.trim();
    if path.is_empty() {
        return Err("path 不能为空".to_string());
    }

    // 读取密钥库明文（导出不修改，因此这里用只读即可）。
    let plain = load_plain_for_read(&app)?;

    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到指定的密钥".to_string())?;

    // 根据导出格式从 parts 中取对应 id 的 value。
    let output = match (&entry.key_type[..], req.format.as_str()) {
        ("AES-256" | "ChaCha20", "key_b64") => keystore::find_part(entry, "symmetric_key_b64")
            .map(|p| p.value.clone())
            .ok_or_else(|| "该对称密钥条目缺少 symmetric_key_b64".to_string())?,
        ("RSA-4096", "private_pem") => keystore::find_part(entry, "rsa_private_pem")
            .map(|p| p.value.clone())
            .ok_or_else(|| "该 RSA 条目缺少私钥，无法导出私钥".to_string())?,
        ("RSA-4096", "public_pem") => keystore::find_part(entry, "rsa_public_pem")
            .map(|p| p.value.clone())
            .ok_or_else(|| "该 RSA 条目缺少公钥，无法导出公钥".to_string())?,
        ("X25519", "public_b64") => keystore::find_part(entry, "x25519_public_b64")
            .map(|p| p.value.clone())
            .ok_or_else(|| "该 X25519 条目缺少公钥，无法导出公钥".to_string())?,
        ("X25519", "json") => {
            #[derive(Serialize)]
            struct X25519Export<'a> {
                secret_b64: Option<&'a str>,
                public_b64: Option<&'a str>,
            }

            let secret = keystore::find_part(entry, "x25519_secret_b64").map(|p| p.value.as_str());
            let public = keystore::find_part(entry, "x25519_public_b64").map(|p| p.value.as_str());

            serde_json::to_string_pretty(&X25519Export {
                secret_b64: secret,
                public_b64: public,
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
pub fn keystore_delete_key(app: AppHandle, req: DeleteKeyRequest) -> Result<(), String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    with_plain_mutation(&app, |plain| {
        let removed = keystore::delete_entry(plain, id);
        if !removed {
            return Err("未找到指定的密钥".to_string());
        }
        Ok(())
    })
}

// =====================
// 内部辅助：读取/写入（明文密钥库）
// =====================

/// 只读获取密钥库明文：
/// - 本项目已移除“应用锁/密钥库加密”，因此这里直接从磁盘读取明文结构。
fn load_plain_for_read(app: &AppHandle) -> Result<keystore::KeyStorePlain, String> {
    keystore::ensure_exists(app).map_err(|e| e.to_string())?;
    keystore::read_plain(app).map_err(|e| e.to_string())
}

/// 对密钥库明文进行一次“可持久化的修改”：
/// - 修改后会写回到磁盘（明文 JSON）。
fn with_plain_mutation<T>(
    app: &AppHandle,
    f: impl FnOnce(&mut keystore::KeyStorePlain) -> Result<T, String>,
) -> Result<T, String> {
    keystore::ensure_exists(app).map_err(|e| e.to_string())?;

    let mut plain = keystore::read_plain(app).map_err(|e| e.to_string())?;
    let out = f(&mut plain)?;

    keystore::write_plain(app, &plain).map_err(|e| e.to_string())?;
    Ok(out)
}

/// 密钥预览：用于展示/复制敏感材料。
///
/// 说明：
/// - 这里直接返回 parts（包含 value），因此只应在“用户主动打开预览/详情”时调用；
/// - 密钥列表接口（keystore_list_entries）只返回 parts_present，不返回 value。
#[derive(Debug, Serialize)]
pub struct KeyPreview {
    pub label: String,
    pub key_type: String,
    pub parts: Vec<keystore::KeyPart>,
}

#[derive(Debug, Deserialize)]
pub struct GetKeyPreviewRequest {
    pub id: String,
}

#[tauri::command]
pub fn keystore_get_key_preview(
    app: AppHandle,
    req: GetKeyPreviewRequest,
) -> Result<KeyPreview, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    let plain = load_plain_for_read(&app)?;
    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到该密钥".to_string())?;

    Ok(KeyPreview {
        label: entry.label.clone(),
        key_type: entry.key_type.clone(),
        parts: entry.parts.clone(),
    })
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
    /// 条目的所有 parts（包含 value）。
    pub parts: Vec<keystore::KeyPart>,
}

#[derive(Debug, Deserialize)]
pub struct GetKeyDetailRequest {
    pub id: String,
}

#[tauri::command]
pub fn keystore_get_key_detail(
    app: AppHandle,
    req: GetKeyDetailRequest,
) -> Result<KeyDetail, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    let plain = load_plain_for_read(&app)?;
    let entry = keystore::find_entry(&plain, id).ok_or_else(|| "未找到该密钥".to_string())?;

    Ok(KeyDetail {
        id: entry.id.clone(),
        label: entry.label.clone(),
        key_type: entry.key_type.clone(),
        parts: entry.parts.clone(),
    })
}

/// 前端“手动导入/编辑保存”用的请求（通用 parts 结构）：
///
/// 说明：
/// - 不再写死 symmetric_key_b64 / rsa_public_pem 等固定字段；
/// - 具体“需要哪些 parts、哪些是必填、如何校验/规范化”由对应算法文件决定。
#[derive(Debug, Deserialize)]
pub struct UpsertKeyRequest {
    pub key_type: String,
    pub label: String,
    pub parts: Vec<keystore::KeyPart>,
}

/// 将前端提交的 parts 做“最基础清洗 + 算法级校验/规范化”。
///
/// 说明：
/// - 基础清洗：过滤掉 value 为空的 part（等价于“未填写/被清空”）。
/// - 算法级校验/规范化：由 crypto_algorithms 内每个算法文件实现（spec.normalize_parts）。
fn normalize_parts_for_upsert(
    key_type: &str,
    parts: Vec<keystore::KeyPart>,
) -> Result<Vec<keystore::KeyPart>, String> {
    let key_type = key_type.trim();
    if key_type.is_empty() {
        return Err("key_type 不能为空".to_string());
    }

    let spec = crate::crypto_algorithms::spec_by_id(key_type)
        .ok_or_else(|| format!("不支持的 key_type：{key_type}"))?;

    let cleaned = parts
        .into_iter()
        .filter(|p| !p.value.trim().is_empty())
        .collect::<Vec<_>>();

    (spec.normalize_parts)(cleaned)
}

#[tauri::command]
pub fn keystore_import_key_manual(
    app: AppHandle,
    req: UpsertKeyRequest,
) -> Result<KeyEntryPublic, String> {
    let label = req.label.trim();
    if label.is_empty() {
        return Err("请输入密钥名称".to_string());
    }
    let key_type = req.key_type.trim();
    if key_type.is_empty() {
        return Err("key_type 不能为空".to_string());
    }
    let parts = normalize_parts_for_upsert(key_type, req.parts)?;

    with_plain_mutation(&app, |plain| {
        let id = keystore::generate_entry_id();

        plain.key_entries.push(keystore::KeyEntry {
            id: id.clone(),
            label: label.to_string(),
            key_type: key_type.to_string(),
            parts: parts.clone(),
        });

        Ok(KeyEntryPublic {
            id,
            label: label.to_string(),
            key_type: key_type.to_string(),
            parts_present: parts.iter().map(|p| p.id.clone()).collect(),
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
    let key_type = req.data.key_type.trim();
    if key_type.is_empty() {
        return Err("key_type 不能为空".to_string());
    }
    let parts = normalize_parts_for_upsert(key_type, req.data.parts)?;

    with_plain_mutation(&app, |plain| {
        let entry = plain
            .key_entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "未找到该密钥".to_string())?;

        entry.label = label.to_string();
        entry.key_type = key_type.to_string();
        entry.parts = parts.clone();

        Ok(KeyEntryPublic {
            id: entry.id.clone(),
            label: entry.label.clone(),
            key_type: entry.key_type.clone(),
            parts_present: entry.parts.iter().map(|p| p.id.clone()).collect(),
        })
    })
}

// =====================
// ML-KEM-768：生成封装密钥（ct）并写入共享密钥（ss）
// =====================

#[derive(Debug, Deserialize)]
pub struct MlKem768GenerateEncapsulationRequest {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct MlKem768GenerateEncapsulationResponse {
    /// 封装密钥（Base64，实际为封装密文 ct）
    pub ct_b64: String,
}

fn upsert_part(entry: &mut keystore::KeyEntry, part: keystore::KeyPart) {
    if let Some(existing) = entry.parts.iter_mut().find(|p| p.id == part.id) {
        *existing = part;
        return;
    }
    entry.parts.push(part);
}

#[tauri::command]
pub fn mlkem768_generate_encapsulation(
    app: AppHandle,
    req: MlKem768GenerateEncapsulationRequest,
) -> Result<MlKem768GenerateEncapsulationResponse, String> {
    let id = req.id.trim();
    if id.is_empty() {
        return Err("id 不能为空".to_string());
    }

    with_plain_mutation(&app, |plain| {
        let entry = plain
            .key_entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "未找到该密钥".to_string())?;

        if entry.key_type != "ML-KEM-768" {
            return Err("该密钥不是 ML-KEM-768 类型".to_string());
        }

        let pub_part = keystore::find_part(entry, "mlkem768_public_b64")
            .ok_or_else(|| "ML-KEM-768 缺少公钥：请先填写/导入公钥".to_string())?;
        if pub_part.encoding != keystore::KeyPartEncoding::Base64 {
            return Err("mlkem768_public_b64 的 encoding 必须为 base64".to_string());
        }

        let (ct_b64, ss_32) =
            crate::crypto_algorithms::mlkem768_encapsulate_to_public_b64(&pub_part.value)?;

        upsert_part(
            entry,
            keystore::KeyPart {
                id: "mlkem768_ct_b64".to_string(),
                encoding: keystore::KeyPartEncoding::Base64,
                value: ct_b64.clone(),
            },
        );
        upsert_part(
            entry,
            keystore::KeyPart {
                id: "mlkem768_shared_b64".to_string(),
                encoding: keystore::KeyPartEncoding::Base64,
                value: base64::engine::general_purpose::STANDARD.encode(ss_32.as_ref()),
            },
        );

        Ok(MlKem768GenerateEncapsulationResponse { ct_b64 })
    })
}

// =====================
// 文本加密/解密（后端执行）
// =====================

/// 文本加密请求：前端只传“算法 + 密钥 + 明文”，加密全部在后端完成。
#[derive(Debug, Deserialize)]
pub struct TextEncryptRequest {
    /// 选择的算法：AES-256 / ChaCha20 / RSA-4096 / X25519 / ML-KEM-768
    pub algorithm: String,
    /// 密钥库条目 id
    pub key_id: String,
    /// 明文输入（UTF-8）
    pub plaintext: String,
}

/// 文本解密请求：前端只传“算法 + 密钥 + 密文(JSON)”，解密全部在后端完成。
#[derive(Debug, Deserialize)]
pub struct TextDecryptRequest {
    /// 选择的算法：AES-256 / ChaCha20 / RSA-4096 / X25519 / ML-KEM-768
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
    req: TextEncryptRequest,
) -> Result<text_crypto::TextEncryptResponse, String> {
    // 读取密钥库明文：用于解析用户所选的 key_id 对应材料。
    let plain = load_plain_for_read(&app)?;

    // 调用专用模块执行加密：避免 commands.rs 继续膨胀。
    text_crypto::encrypt_text(&plain, &req.algorithm, &req.key_id, &req.plaintext)
}

/// 文本解密：返回明文；解密失败统一提示“密钥错误或数据已损坏”。
#[tauri::command]
pub fn text_decrypt(
    app: AppHandle,
    req: TextDecryptRequest,
) -> Result<text_crypto::TextDecryptResponse, String> {
    // 读取密钥库明文：用于解析用户所选的 key_id 对应材料。
    let plain = load_plain_for_read(&app)?;

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

    match &entry.key_type[..] {
        "AES-256" | "ChaCha20" => {
            let part = keystore::find_part(entry, "symmetric_key_b64")
                .ok_or_else(|| "对称密钥条目缺少 symmetric_key_b64".to_string())?;
            if part.encoding != keystore::KeyPartEncoding::Base64 {
                return Err("symmetric_key_b64 的 encoding 必须为 base64".to_string());
            }

            let bytes = base64::engine::general_purpose::STANDARD
                .decode(part.value.trim())
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
        "ML-KEM-768" => {
            // 会话密钥：由 ML-KEM-768 封装/解封建立（32 字节 Base64），这里直接作为数据侧 key 使用。
            let part = keystore::find_part(entry, "mlkem768_shared_b64").ok_or_else(|| {
                "ML-KEM-768 尚未建立会话：请先生成/导入封装密钥并保存".to_string()
            })?;
            if part.encoding != keystore::KeyPartEncoding::Base64 {
                return Err("mlkem768_shared_b64 的 encoding 必须为 base64".to_string());
            }

            let bytes = base64::engine::general_purpose::STANDARD
                .decode(part.value.trim())
                .map_err(|_| "共享密钥 Base64 解码失败".to_string())?;
            if bytes.len() != 32 {
                return Err("共享密钥必须为 32 字节".to_string());
            }
            let mut key_32 = Zeroizing::new([0u8; 32]);
            key_32.copy_from_slice(&bytes);

            Ok(file_crypto::EncryptKeyMaterial::Symmetric {
                alg: entry.key_type.clone(),
                key_32,
            })
        }
        "RSA-4096" => {
            let part = keystore::find_part(entry, "rsa_public_pem")
                .ok_or_else(|| "RSA 加密需要公钥，请选择包含公钥的 RSA 密钥".to_string())?;
            if part.encoding != keystore::KeyPartEncoding::Pem {
                return Err("rsa_public_pem 的 encoding 必须为 pem".to_string());
            }

            Ok(file_crypto::EncryptKeyMaterial::RsaPublic {
                alg: entry.key_type.clone(),
                public_pem: part.value.clone(),
            })
        }
        "X25519" => {
            // 产品规则：X25519 必须同时拥有公钥+私钥才允许加/解密（即使加密只用公钥）。
            if !keystore::has_part(entry, "x25519_public_b64")
                || !keystore::has_part(entry, "x25519_secret_b64")
            {
                return Err("X25519 加密需要公钥+私钥，请选择“完整”类型的 X25519 密钥".to_string());
            }

            let part = keystore::find_part(entry, "x25519_public_b64")
                .ok_or_else(|| "X25519 缺少公钥".to_string())?;
            if part.encoding != keystore::KeyPartEncoding::Base64 {
                return Err("x25519_public_b64 的 encoding 必须为 base64".to_string());
            }

            let pub_bytes = base64::engine::general_purpose::STANDARD
                .decode(part.value.trim())
                .map_err(|_| "X25519 公钥 Base64 解码失败".to_string())?;
            if pub_bytes.len() != 32 {
                return Err("X25519 公钥必须为 32 字节".to_string());
            }
            let mut pub_32 = [0u8; 32];
            pub_32.copy_from_slice(&pub_bytes);

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

    match &entry.key_type[..] {
        "AES-256" | "ChaCha20" => {
            let part = keystore::find_part(entry, "symmetric_key_b64")
                .ok_or_else(|| "对称密钥条目缺少 symmetric_key_b64".to_string())?;
            if part.encoding != keystore::KeyPartEncoding::Base64 {
                return Err("symmetric_key_b64 的 encoding 必须为 base64".to_string());
            }

            let bytes = base64::engine::general_purpose::STANDARD
                .decode(part.value.trim())
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
        "ML-KEM-768" => {
            let part = keystore::find_part(entry, "mlkem768_shared_b64").ok_or_else(|| {
                "ML-KEM-768 尚未建立会话：请先生成/导入封装密钥并保存".to_string()
            })?;
            if part.encoding != keystore::KeyPartEncoding::Base64 {
                return Err("mlkem768_shared_b64 的 encoding 必须为 base64".to_string());
            }

            let bytes = base64::engine::general_purpose::STANDARD
                .decode(part.value.trim())
                .map_err(|_| "共享密钥 Base64 解码失败".to_string())?;
            if bytes.len() != 32 {
                return Err("共享密钥必须为 32 字节".to_string());
            }
            let mut key_32 = Zeroizing::new([0u8; 32]);
            key_32.copy_from_slice(&bytes);

            Ok(file_crypto::DecryptKeyMaterial::Symmetric {
                alg: entry.key_type.clone(),
                key_32,
            })
        }
        "RSA-4096" => {
            let part = keystore::find_part(entry, "rsa_private_pem")
                .ok_or_else(|| "RSA 解密需要私钥，请选择包含私钥的 RSA 密钥".to_string())?;
            if part.encoding != keystore::KeyPartEncoding::Pem {
                return Err("rsa_private_pem 的 encoding 必须为 pem".to_string());
            }

            Ok(file_crypto::DecryptKeyMaterial::RsaPrivate {
                private_pem: part.value.clone(),
            })
        }
        "X25519" => {
            // 产品规则：X25519 必须同时拥有公钥+私钥才允许加/解密（即使解密只用私钥）。
            if !keystore::has_part(entry, "x25519_public_b64")
                || !keystore::has_part(entry, "x25519_secret_b64")
            {
                return Err("X25519 解密需要公钥+私钥，请选择“完整”类型的 X25519 密钥".to_string());
            }

            let part = keystore::find_part(entry, "x25519_secret_b64")
                .ok_or_else(|| "X25519 缺少私钥".to_string())?;
            if part.encoding != keystore::KeyPartEncoding::Base64 {
                return Err("x25519_secret_b64 的 encoding 必须为 base64".to_string());
            }

            let sec_bytes = base64::engine::general_purpose::STANDARD
                .decode(part.value.trim())
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
    let plain = load_plain_for_read(&app)?;

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
    let plain = load_plain_for_read(&app)?;

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
