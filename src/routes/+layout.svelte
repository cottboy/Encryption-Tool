<!--
  应用主布局：
  - 顶部提供“三标签页”导航（密钥管理 / 文本加密 / 文件加密）。
  - 风格要求：简约、扁平化，不使用卡片堆叠与浓重阴影。
  - 增加“应用锁（密钥库加密）”的锁屏层：启用后启动必须先解锁。
-->

<script lang="ts">
  import "../app.css";

  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  import { locale, setLocale, supportedLocales, t, type SupportedLocale } from "$lib/i18n";
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

  function isActive(pathname: string, tabPath: string): boolean {
    if (tabPath === "/") return pathname === "/";
    return pathname.startsWith(tabPath);
  }

  async function onLocaleChange(e: Event) {
    const value = (e.target as HTMLSelectElement).value as SupportedLocale;
    await setLocale(value);
  }

  // =====================
  // 应用锁（锁屏层）
  // =====================

  type KeyStoreStatus = {
    exists: boolean;
    encrypted: boolean;
    unlocked: boolean;
    version: number;
    key_count: number | null;
  };

  // 当前锁状态。
  let status = $state<KeyStoreStatus | null>(null);

  // 解锁输入框（只在锁屏层显示）。
  let unlockPassword = $state("");

  // 锁屏层错误提示。
  let lockError = $state<string>("");

  async function refreshStatus() {
    status = await invoke<KeyStoreStatus>("keystore_status");
  }

  async function unlock() {
    lockError = "";
    await invoke("keystore_unlock", { password: unlockPassword });
    unlockPassword = "";
    await refreshStatus();

    // 解锁成功后通知页面刷新（例如密钥列表重载）。
    window.dispatchEvent(new CustomEvent("keystore_status_changed"));
  }

  onMount(() => {
    // 启动时刷新一次状态。
    refreshStatus().catch(() => {
      // 忽略：失败时不阻塞 UI。
    });

    // 监听子页面发出的“密钥库状态变更”事件。
    const handler = () => {
      refreshStatus().catch(() => {
        // 忽略：失败时不阻塞 UI。
      });
    };

    window.addEventListener("keystore_status_changed", handler);

    return () => {
      window.removeEventListener("keystore_status_changed", handler);
    };
  });

  // 当密钥库加密且未解锁时：认为应用处于“锁屏”。
  $effect(() => {
    if (!status) return;
    if (!status.encrypted) {
      lockError = "";
      unlockPassword = "";
    }
  });
</script>

<div class="app">
  <header class="topbar">
    <div class="topbar-inner container">
      <!--
        顶部栏布局（macOS 风格）：
        - 左：应用名
        - 中：主功能分段控件（密钥管理 / 文本加密 / 文件加密）
        - 右：语言切换
        这样可以让分段控件在视觉上“居中且对称”，避免挤在一侧造成廉价感。
      -->
      <div class="topbar-left">
        <div class="brand">{$t("app.title")}</div>
      </div>

      <nav class="tabs" aria-label="主功能标签">
        {#each tabs as tab}
          <a
            class="tab {isActive($page.url.pathname, tab.path) ? 'active' : ''}"
            href={tab.path}
            aria-disabled={status?.encrypted && !status?.unlocked}
          >
            {$t(tab.labelKey)}
          </a>
        {/each}
      </nav>

      <div class="topbar-right locale">
        <select aria-label="语言" onchange={onLocaleChange} bind:value={$locale}>
          {#each supportedLocales as loc}
            <option value={loc}>{loc}</option>
          {/each}
        </select>
      </div>
    </div>
  </header>

  <main class="main">
    <div class="container">
      {@render children()}
    </div>
  </main>

  {#if status?.encrypted && !status?.unlocked}
    <!--
      锁屏层：
      - 覆盖整个应用内容。
      - 不使用“卡片堆叠”，只用留白 + 细边框。
    -->
    <div class="lock" aria-label="应用已锁定">
      <div class="lock-inner">
        <div class="lock-title">{$t("lock.title")}</div>
        <div class="help">{$t("lock.subtitle")}</div>

        <div class="lock-row">
          <input
            type="password"
            bind:value={unlockPassword}
            placeholder={$t("lock.passwordPlaceholder")}
            onkeydown={(e) => {
              if (e.key === "Enter") {
                unlock().catch((err) => {
                  lockError = typeof err === "string" ? err : String(err);
                });
              }
            }}
          />
          <button
            class="primary"
            onclick={async () => {
              try {
                await unlock();
              } catch (e) {
                lockError = typeof e === "string" ? e : String(e);
              }
            }}
          >
            {$t("lock.unlock")}
          </button>
        </div>

        {#if lockError}
          <div class="help" style="color: #b42318">{lockError}</div>
        {/if}
      </div>
    </div>
  {/if}
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
    /*
      macOS 顶部栏常见布局：左右各一组控件，中间主控件居中。
      使用三列 grid 可以做到“真居中”，不会因为右侧控件宽度变化而偏移。
    */
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    align-items: center;
    column-gap: 12px;
  }

  .brand {
    font-size: 13px;
    font-weight: 600;
    user-select: none;
    white-space: nowrap;
  }

  .topbar-left {
    justify-self: start;
    display: flex;
    align-items: center;
    min-width: 0;
  }

  .topbar-right {
    justify-self: end;
    display: flex;
    align-items: center;
    min-width: 0;
  }

  /*
    标签页：macOS 风格分段控件（Segmented Control）
    目标：
    - 去掉“卡片嵌套感”（外层胶囊 + 内层胶囊的双重边框/阴影）
    - 视觉上更接近原生：淡底、轻边框、选中项白底浮起
    - 位置保持居中，对称一致
  */
  .tabs {
    justify-self: center;
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

  .tab[aria-disabled="true"] {
    pointer-events: none;
    opacity: 0.55;
  }

  .locale select {
    font-size: 12px;
    /*
      语言选择下拉框属于“紧凑控件”，本地需要覆盖全局的 padding：
      - 但全局 select 会为自定义箭头预留右侧空间（padding-right）。
      - 这里必须把 padding-right 单独补回来，否则文字会被箭头遮挡，也会显得“贴边”。
    */
    /*
      全局单选 select 会固定高度为 40px 来保证文字垂直居中（更稳定），
      但顶部语言切换需要更紧凑，因此这里覆盖为更小的高度与对应的 line-height。
    */
    height: 30px;
    padding: 0 28px 0 10px;
    line-height: 28px;

    /* 对齐紧凑尺寸下的箭头位置：右侧留白更自然 */
    background-position: right 10px center;
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

  /* 锁屏层 */
  .lock {
    position: fixed;
    inset: 0;
    background: rgba(245, 245, 247, 0.92);
    backdrop-filter: blur(10px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .lock-inner {
    width: 100%;
    max-width: 520px;
    padding: 18px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: rgba(255, 255, 255, 0.75);
  }

  .lock-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 6px;
  }

  .lock-row {
    display: flex;
    gap: 10px;
    margin-top: 12px;
  }

  .lock-row input {
    flex: 1;
  }
</style>
