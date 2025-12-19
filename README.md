# Encryption Tool

跨平台图形化加密工具（Windows / macOS / Linux）。

## 目标（当前阶段）

- 三标签页 UI：密钥管理 / 文本加密 / 文件加密
- i18n 翻译文件接口：`static/locales/*.json`
- 加密逻辑全部放在 Rust 后端（Tauri 命令），前端只负责交互与展示

## 开发运行

在 `encryption-tool/` 目录下：

```bash
npm install
npm run tauri dev
```

## 自检

```bash
npm run check
npm run build
cd src-tauri && cargo check
```
