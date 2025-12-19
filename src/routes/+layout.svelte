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
      <div class="brand">{$t("app.title")}</div>

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

      <div class="spacer"></div>

      <div class="locale">
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
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .brand {
    font-size: 13px;
    font-weight: 600;
    user-select: none;
    white-space: nowrap;
  }

  /* 标签页：胶囊分段控件，扁平化 */
  .tabs {
    display: flex;
    gap: 6px;
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.7);
  }

  .tab {
    text-decoration: none;
    color: var(--muted);
    font-size: 13px;
    padding: 6px 12px;
    border-radius: 999px;
    border: 1px solid transparent;
  }

  .tab:hover {
    color: var(--text);
    border-color: var(--border);
  }

  .tab.active {
    color: var(--text);
    background: #ffffff;
    border-color: var(--border);
  }

  .spacer {
    flex: 1;
  }

  .locale select {
    font-size: 12px;
    padding: 6px 10px;
  }

  .main {
    padding: 16px 0;
    flex: 1;
    overflow: auto;
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
