// Windows release 模式下防止额外控制台窗口弹出（Tauri 官方推荐写法），不要删除。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // 入口：实际的 Tauri 启动逻辑在 lib.rs 的 run() 中。
    encryption_tool_lib::run()
}
