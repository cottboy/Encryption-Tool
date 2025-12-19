/*
  Tauri 后端入口（Rust）：
  - 需求要求：加密操作必须放在后端（Rust）执行，前端只负责 UI 与参数收集。
  - 这里注册所有可被前端 invoke 的命令，并初始化需要的插件。
*/

mod commands;
mod keystore;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // 管理应用状态：保存“本次运行是否已解锁密钥库”，以及加密库写回所需的会话信息。
        .manage(AppState::default())
        // 插件：
        // - opener：打开外部链接
        // - dialog：文件选择/保存（导入/导出密钥用）
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            // 基础连通性
            commands::health_check,
            // 算法列表
            commands::get_supported_algorithms,
            // 密钥库/应用锁
            commands::keystore_status,
            commands::keystore_unlock,
            commands::keystore_lock,
            commands::keystore_set_lock,
            commands::keystore_list_entries,
            commands::keystore_get_key_preview,
            // 密钥：生成/导入/导出/删除
            commands::keystore_generate_key,
            commands::keystore_import_key,
            commands::keystore_export_key,
            commands::keystore_delete_key,
        ])
        .run(tauri::generate_context!())
        .expect("运行 Tauri 应用时发生错误");
}


