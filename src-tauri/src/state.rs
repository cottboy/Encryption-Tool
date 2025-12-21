/*
  应用运行时状态（AppState）：
  - 需求要求：如果用户启用了密钥库加密，那么下次打开软件必须像手机锁屏一样先解锁。

  关键点：
  - 为了让“解锁后可以持续使用”成立：
    - 如果密钥库启用了加密，我们必须在本次运行内缓存“可用于重新加密写回”的信息。
    - 否则每次新增/删除密钥都无法写回到加密文件（因为没有密码/派生密钥）。

  安全取舍：
  - 我们不在内存中长期保存用户明文密码。
  - 解锁时通过 Argon2id 派生 32 字节密钥，并将“派生后的密钥”缓存于内存。
  - 用户主动锁定或退出应用时，缓存会被清空；从而达到“下次启动必须再次输入密码”。
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

use zeroize::Zeroizing;

use crate::keystore::{KdfParams, KeyStorePlain};

/// 已解锁会话：
/// - Plain：密钥库未加密（或已移除应用锁）
/// - Encrypted：密钥库启用了应用锁（会缓存派生密钥以便写回）
#[derive(Debug, Clone)]
pub enum UnlockedKeystore {
    Plain(KeyStorePlain),

    Encrypted {
        /// 已解锁的密钥库明文（仅在本次运行内有效）。
        plain: KeyStorePlain,

        /// KDF 参数（包含 salt 等），用于描述该密钥库当前的加密配置。
        /// 说明：
        /// - 我们写回加密文件时会复用该 salt/参数（nonce 会每次重新生成）。
        kdf: KdfParams,

        /// 由用户密码派生出来的 32 字节密钥（会话内缓存）。
        derived_key: Zeroizing<[u8; 32]>,
    },
}

/// 文件加密/解密任务控制块：
/// - cancel：原子取消标记（前端点击取消后置为 true）
#[derive(Debug, Clone)]
pub struct FileCryptoTaskControl {
    pub cancel: Arc<AtomicBool>,
}

pub struct AppState {
    /// 已解锁的密钥库会话（仅在本次运行内有效）。
    pub unlocked_keystore: Mutex<Option<UnlockedKeystore>>,

    /// 文件加密/解密任务集合：
    /// - key：task_id（前端用于订阅进度、以及取消）
    /// - value：任务控制块（目前只包含 cancel 标记）
    pub file_crypto_tasks: Mutex<HashMap<String, FileCryptoTaskControl>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            unlocked_keystore: Mutex::new(None),
            file_crypto_tasks: Mutex::new(HashMap::new()),
        }
    }
}


