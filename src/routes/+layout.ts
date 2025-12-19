// 说明：
// - Tauri 不提供 Node.js 服务端来做 SSR，因此这里将 SvelteKit 配置为纯 SPA（ssr=false）。
// - 通过 adapter-static + fallback 到 index.html 的方式，保证路由在桌面环境正常工作。
// - 参考：https://svelte.dev/docs/kit/single-page-apps
// - 参考：https://v2.tauri.app/start/frontend/sveltekit/
export const ssr = false;
