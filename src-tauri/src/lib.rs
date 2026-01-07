/*
  Tauri 后端入口（Rust）：
  - 需求要求：加密操作必须放在后端（Rust）执行，前端只负责 UI 与参数收集。
  - 这里注册所有可被前端 invoke 的命令，并初始化需要的插件。
*/

mod commands;
mod crypto_algorithms;
mod file_crypto;
mod keystore;
mod state;
mod text_crypto;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // 管理应用状态：保存文件加密/解密任务的运行中状态（用于进度与取消）。
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
            // 算法声明（用于 UI 动态表单）
            commands::get_algorithm_form_specs,
            // 密钥库
            commands::keystore_status,
            commands::keystore_list_entries,
            commands::keystore_get_key_preview,
            commands::keystore_get_key_detail,
            // 密钥：生成/导入/导出/删除
            commands::keystore_generate_key,
            commands::keystore_import_key,
            commands::keystore_import_key_manual,
            commands::keystore_export_key,
            commands::keystore_delete_key,
            commands::keystore_update_key,
            // ML-KEM-768：封装（生成封装密钥 + 写入共享密钥）
            commands::mlkem768_generate_encapsulation,
            // 文本加密/解密（后端执行）
            commands::text_encrypt,
            commands::text_decrypt,
            // 文件加密/解密（后端执行，流式分块）
            commands::file_encrypt_start,
            commands::file_decrypt_start,
            commands::file_crypto_cancel,
        ])
        .run(tauri::generate_context!())
        .expect("运行 Tauri 应用时发生错误");
}
