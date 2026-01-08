<!--
  应用主布局：
  - 顶部提供“三标签页”导航（密钥管理 / 文本加密 / 文件加密）。
  - 风格要求：简约、扁平化，不使用卡片堆叠与浓重阴影。
  - 说明：本项目已移除“应用锁/密钥库加密”，因此不再需要锁屏层。
-->

<script lang="ts">
  import "../app.css";

  import { t } from "$lib/i18n";
  import { page } from "$app/stores";

  // Svelte 5：布局内容通过 children 渲染，替代 <slot />。
  let { children } = $props();

  // =====================
  // 顶部 Tab
  // =====================

  const tabs = [
    { path: "/", labelKey: "app.tabs.keys" },
    { path: "/text", labelKey: "app.tabs.text" },
    { path: "/files", labelKey: "app.tabs.files" }
  ] as const;

  // 根据当前语言实时更新窗口标题（Tauri WebView 会读取 document.title）。
  $effect(() => {
    if (typeof document === "undefined") return;
    document.title = $t("app.title");
  });

  function isActive(pathname: string, tabPath: string): boolean {
    if (tabPath === "/") return pathname === "/";
    return pathname.startsWith(tabPath);
  }
</script>

<div class="app">
  <header class="topbar">
    <div class="topbar-inner container">
      <!--
        顶部栏布局（macOS 风格）：
        - 仅保留中间分段控件（居中）
        说明：
        - 已移除左上角“Encryption Tool”字样；
        - 已移除右上角语言切换，下方 i18n 会按系统语言自动选择。
      -->
      <nav class="tabs" aria-label={$t("app.a11y.mainTabs")}>
        {#each tabs as tab}
          <a
            class="tab {isActive($page.url.pathname, tab.path) ? 'active' : ''}"
            href={tab.path}
          >
            {$t(tab.labelKey)}
          </a>
        {/each}
      </nav>
    </div>
  </header>

  <main class="main">
    <div class="container">
      {@render children()}
    </div>
  </main>
</div>

<style>
  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .topbar {
    background: rgba(255, 255, 255, 0.75);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border);
  }

  .topbar-inner {
    height: 52px;
    /* 仅保留中间分段控件，用 flex 做居中布局 */
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /*
    标签页：macOS 风格分段控件（Segmented Control）
    目标：
    - 去掉“卡片嵌套感”（外层胶囊 + 内层胶囊的双重边框/阴影）
    - 视觉上更接近原生：淡底、轻边框、选中项白底浮起
    - 位置保持居中，对称一致
  */
  .tabs {
    display: inline-flex;
    gap: 2px;
    padding: 3px;
    border-radius: 10px;
    background: rgba(118, 118, 128, 0.12);
    border: 1px solid rgba(60, 60, 67, 0.12);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.55);
  }

  .tab {
    text-decoration: none;
    color: rgba(60, 60, 67, 0.78);
    font-size: 13px;
    padding: 6px 14px;
    border-radius: 8px;
    line-height: 16px;
    user-select: none;
    white-space: nowrap;
    transition:
      background 120ms ease,
      box-shadow 120ms ease,
      color 120ms ease;
  }

  .tab:hover {
    color: rgba(60, 60, 67, 0.92);
    background: rgba(118, 118, 128, 0.10);
  }

  .tab.active {
    color: rgba(60, 60, 67, 0.92);
    background: rgba(255, 255, 255, 0.92);
    box-shadow:
      0 1px 1px rgba(0, 0, 0, 0.10),
      inset 0 1px 0 rgba(255, 255, 255, 0.70);
  }

  .main {
    padding: 16px 0;
    flex: 1;

    /*
      统一滚动容器：
      - 纵向允许滚动：承载各页面内容。
      - 横向禁止滚动：避免因“某个元素轻微超宽”导致出现横向滚动条（并连带触发额外的纵向滚动条）。
      - min-height: 0：修复 flex 容器中子项默认最小高度导致的溢出问题（常见于出现“看起来不该滚动却在滚动”）。
    */
    min-height: 0;
    overflow-y: auto;
    overflow-x: hidden;
  }

</style>
