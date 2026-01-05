/*
  应用运行时状态（AppState）：
  - 说明：本项目已移除“应用锁/密钥库加密”，因此 AppState 不再需要保存任何“解锁会话/派生密钥”。
  - 当前 AppState 只负责保存“文件加密/解密任务”的运行中状态（用于进度与取消）。
*/

/*
  补充：文件加密任务状态
  - 需求要求：文件加密/解密必须支持进度显示与可取消。
  - 实现策略：每次开始文件任务时生成 task_id，并在内存里记录一个 cancel 标记。
  - 前端通过 invoke(cancel) 触发取消；后端在流式分块循环中轮询该标记并尽快停止。
*/

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// 文件加密/解密任务控制块：
/// - cancel：原子取消标记（前端点击取消后置为 true）
#[derive(Debug, Clone)]
pub struct FileCryptoTaskControl {
    pub cancel: Arc<AtomicBool>,
}

pub struct AppState {
    /// 文件加密/解密任务集合：
    /// - key：task_id（前端用于订阅进度、以及取消）
    /// - value：任务控制块（目前只包含 cancel 标记）
    pub file_crypto_tasks: Mutex<HashMap<String, FileCryptoTaskControl>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            file_crypto_tasks: Mutex::new(HashMap::new()),
        }
    }
}
