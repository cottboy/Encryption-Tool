<!--
  密钥管理（单一 keystore）：
  - 顶部一排按钮：生成密钥 / 导入密钥 / 加密密钥（应用锁）
  - 下方全宽密钥列表：每行提供“预览（小眼睛）/ 导出”
  - 说明：敏感材料始终在后端读取与处理；前端只做展示与文件选择
-->

<script lang="ts">
  import { onMount } from "svelte";

  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";

  import { t } from "$lib/i18n";

  type KeyStoreStatus = {
    exists: boolean;
    encrypted: boolean;
    unlocked: boolean;
    version: number;
    key_count: number | null;
  };

  type KeyEntryPublic = {
    id: string;
    label: string;
    key_type: string;
    material_kind: string;
  };

  type KeyPreview =
    | { kind: "symmetric"; label: string; algorithm: string; key_b64: string }
    | { kind: "rsa"; label: string; material_kind: string; public_pem: string; private_pem: string | null }
    | { kind: "x25519"; label: string; public_b64: string; secret_b64: string };

  const supportedTypes = ["AES-256", "ChaCha20", "RSA", "X25519"] as const;
  type SupportedType = (typeof supportedTypes)[number];

  type ExportFormat = "key_b64" | "private_pem" | "public_pem" | "json" | "public_b64";

  let status = $state<KeyStoreStatus | null>(null);
  let entries = $state<KeyEntryPublic[]>([]);

  let message = $state("");

  // Dialog state
  let showGenerate = $state(false);
  let showImport = $state(false);
  let showLock = $state(false);
  let showPreview = $state(false);
  let showExport = $state(false);

  // 统一处理“关闭弹窗”，用于键盘 ESC。
  function closeTopModal() {
    if (showExport) {
      showExport = false;
      return;
    }
    if (showPreview) {
      showPreview = false;
      return;
    }
    if (showLock) {
      showLock = false;
      return;
    }
    if (showImport) {
      showImport = false;
      return;
    }
    if (showGenerate) {
      showGenerate = false;
    }
  }

  // Generate
  let genType = $state<SupportedType>("AES-256");
  let genLabel = $state("");

  // Import
  let importType = $state<SupportedType>("AES-256");
  let importLabel = $state("");

  // Lock (encrypt keystore)
  let lockPassword = $state("");
  let lockPassword2 = $state("");

  // Preview
  let preview = $state<KeyPreview | null>(null);
  let previewShowSecret = $state(false);

  // Export
  let exportEntry = $state<KeyEntryPublic | null>(null);
  let exportFormat = $state<ExportFormat>("key_b64");

  // 键盘快捷键：当任意弹窗开启时，按 ESC 关闭。
  $effect(() => {
    const anyOpen = showGenerate || showImport || showLock || showPreview || showExport;
    if (!anyOpen) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeTopModal();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  });

  function formatError(err: unknown): string {
    if (typeof err === "string") return err;
    if (err && typeof err === "object" && "message" in err) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const msg = (err as any).message;
      if (typeof msg === "string") return msg;
    }
    return String(err);
  }

  function notifyKeystoreChanged() {
    window.dispatchEvent(new CustomEvent("keystore_status_changed"));
  }

  async function refresh() {
    message = "";
    status = await invoke<KeyStoreStatus>("keystore_status");

    try {
      entries = await invoke<KeyEntryPublic[]>("keystore_list_entries");
    } catch {
      entries = [];
    }
  }

  function openLockDialog() {
    lockPassword = "";
    lockPassword2 = "";
    showLock = true;
  }

  async function applyLock() {
    message = "";

    const pw = lockPassword.trim();
    const pw2 = lockPassword2.trim();

    if (!pw) {
      message = $t("keys.ui.errors.passwordRequired");
      return;
    }

    if (pw !== pw2) {
      message = $t("keys.ui.errors.passwordMismatch");
      return;
    }

    await invoke("keystore_set_lock", { newPassword: pw });

    showLock = false;
    await refresh();
    notifyKeystoreChanged();
  }

  async function removeLock() {
    message = "";
    await invoke("keystore_set_lock", { newPassword: null });
    showLock = false;
    await refresh();
    notifyKeystoreChanged();
  }

  async function doGenerate() {
    message = "";

    await invoke("keystore_generate_key", {
      req: {
        key_type: genType,
        label: genLabel.trim() ? genLabel.trim() : null
      }
    });

    showGenerate = false;
    genLabel = "";
    await refresh();
    notifyKeystoreChanged();
  }

  async function doImport() {
    message = "";

    const name = importLabel.trim();
    if (!name) {
      message = $t("keys.ui.errors.nameRequired");
      return;
    }

    const picked = await open({ multiple: false, directory: false });
    if (!picked || typeof picked !== "string") return;

    await invoke("keystore_import_key", {
      req: {
        key_type: importType,
        label: name,
        path: picked
      }
    });

    showImport = false;
    importLabel = "";
    await refresh();
    notifyKeystoreChanged();
  }

  function openPreviewDialog(entry: KeyEntryPublic) {
    preview = null;
    previewShowSecret = false;
    showPreview = true;

    invoke<KeyPreview>("keystore_get_key_preview", { req: { id: entry.id } })
      .then((p) => {
        preview = p;
      })
      .catch((e) => {
        message = formatError(e);
        showPreview = false;
      });
  }

  function defaultExportFormatFor(entry: KeyEntryPublic): ExportFormat {
    if (entry.material_kind === "rsa_private") return "private_pem";
    if (entry.material_kind === "rsa_public") return "public_pem";
    if (entry.material_kind === "x25519") return "json";
    return "key_b64";
  }

  function availableExportFormats(entry: KeyEntryPublic): { value: ExportFormat; label: string }[] {
    if (entry.material_kind === "rsa_private") {
      return [
        { value: "private_pem", label: $t("keys.ui.formats.rsa_private_pem") },
        { value: "public_pem", label: $t("keys.ui.formats.rsa_public_pem") }
      ];
    }

    if (entry.material_kind === "rsa_public") {
      return [{ value: "public_pem", label: $t("keys.ui.formats.rsa_public_pem") }];
    }

    if (entry.material_kind === "x25519") {
      return [
        { value: "json", label: $t("keys.ui.formats.x25519_json") },
        { value: "public_b64", label: $t("keys.ui.formats.x25519_public_b64") }
      ];
    }

    return [{ value: "key_b64", label: $t("keys.ui.formats.key_b64") }];
  }

  function getDefaultExportName(entry: KeyEntryPublic, fmt: ExportFormat): string {
    const base = entry.label || "key";
    if (entry.key_type === "RSA") {
      return fmt === "public_pem" ? `${base}.public.pem` : `${base}.private.pem`;
    }
    if (entry.key_type === "X25519") {
      return fmt === "public_b64" ? `${base}.public.txt` : `${base}.x25519.json`;
    }
    return `${base}.key.txt`;
  }

  function openExportDialog(entry: KeyEntryPublic) {
    exportEntry = entry;
    exportFormat = defaultExportFormatFor(entry);
    showExport = true;
  }

  async function doExport() {
    message = "";
    if (!exportEntry) return;

    const target = await save({ defaultPath: getDefaultExportName(exportEntry, exportFormat) });
    if (!target || typeof target !== "string") return;

    await invoke("keystore_export_key", {
      req: {
        id: exportEntry.id,
        format: exportFormat,
        path: target
      }
    });

    showExport = false;
    message = $t("keys.ui.msg.exported", { path: target });
  }

  onMount(() => {
    refresh().catch((e) => {
      message = formatError(e);
    });

    const handler = () => {
      refresh().catch(() => {
        // ignored
      });
    };
    window.addEventListener("keystore_status_changed", handler);

    return () => {
      window.removeEventListener("keystore_status_changed", handler);
    };
  });
</script>

<h1 class="h1">{$t("keys.title")}</h1>
<p class="help">{$t("keys.desc")}</p>

<div class="toolbar" style="margin-top: 12px">
  <button class="primary" onclick={() => {
    message = "";
    showGenerate = true;
  }}>{$t("keys.ui.generateTitle")}</button>

  <button onclick={() => {
    message = "";
    showImport = true;
  }}>{$t("keys.ui.importTitle")}</button>

  <button onclick={() => {
    message = "";
    openLockDialog();
  }}>{status?.encrypted ? $t("keys.ui.disableLock") : $t("keys.ui.enableLock")}</button>

  <div class="help" style="margin-left: 6px">
    {#if status?.encrypted}
      {status.unlocked ? $t("keys.ui.enabledUnlocked") : $t("keys.ui.enabledLocked")}
    {:else}
      {$t("keys.ui.disabled")}
    {/if}
  </div>
</div>

<div class="divider" style="margin: 14px 0"></div>

<div class="list">
  {#if entries.length === 0}
    <p class="help">{$t("keys.ui.emptyKeys")}</p>
    <p class="help">{$t("keys.ui.emptyHint")}</p>
  {:else}
    <table class="table">
      <thead>
        <tr>
          <th style="width: 60%">{$t("common.name")}</th>
          <th style="width: 20%">{$t("common.type")}</th>
          <th style="width: 20%">{$t("common.actions")}</th>
        </tr>
      </thead>
      <tbody>
        {#each entries as e}
          <tr>
            <td>{e.label}</td>
            <td class="mono">{e.key_type}</td>
            <td class="actions">
              <button class="icon" aria-label={$t("keys.ui.actions.preview")} onclick={() => openPreviewDialog(e)}>
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>

              <button class="icon" aria-label={$t("keys.ui.actions.export")} onclick={() => openExportDialog(e)}>
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if message}
  <div class="divider" style="margin: 14px 0"></div>
  <p class="help">{message}</p>
{/if}

<!-- Modals (flat) -->
{#if showGenerate}
  <div class="modal" role="presentation">
    <div class="modal-inner" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t("keys.ui.generateTitle")}>
      <div class="modal-title">{$t("keys.ui.generateTitle")}</div>
      <div class="grid2" style="margin-top: 10px">
        <div>
          <div class="label">{$t("common.algorithm")}</div>
          <select bind:value={genType}>
            {#each supportedTypes as tp}
              <option value={tp}>{tp}</option>
            {/each}
          </select>
        </div>
        <div>
          <div class="label">{$t("common.name")}</div>
          <input bind:value={genLabel} placeholder="" />
        </div>
      </div>
      <div class="toolbar" style="margin-top: 12px">
        <button class="primary" onclick={async () => {
          try {
            await doGenerate();
          } catch (e) {
            message = formatError(e);
          }
        }}>{$t("common.ok")}</button>
        <button onclick={() => (showGenerate = false)}>{$t("common.cancel")}</button>
      </div>
    </div>
  </div>
{/if}

{#if showImport}
  <div class="modal" role="presentation">
    <div class="modal-inner" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t("keys.ui.importTitle")}>
      <div class="modal-title">{$t("keys.ui.importTitle")}</div>
      <div class="grid2" style="margin-top: 10px">
        <div>
          <div class="label">{$t("common.algorithm")}</div>
          <select bind:value={importType}>
            {#each supportedTypes as tp}
              <option value={tp}>{tp}</option>
            {/each}
          </select>
        </div>
        <div>
          <div class="label">{$t("keys.ui.importNameLabel")}</div>
          <input bind:value={importLabel} placeholder="" />
        </div>
      </div>
      <div class="toolbar" style="margin-top: 12px">
        <button class="primary" onclick={async () => {
          try {
            await doImport();
          } catch (e) {
            message = formatError(e);
          }
        }}>{$t("keys.ui.chooseFile")}</button>
        <button onclick={() => (showImport = false)}>{$t("common.cancel")}</button>
      </div>
    </div>
  </div>
{/if}

{#if showLock}
  <div class="modal" role="presentation">
    <div class="modal-inner" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t("keys.ui.lockTitle")}>
      <div class="modal-title">{$t("keys.ui.lockTitle")}</div>

      {#if status?.encrypted}
        <p class="help">{$t("keys.ui.disableHint")}</p>
        <div class="toolbar" style="margin-top: 12px">
          <button class="primary" onclick={async () => {
            try {
              await removeLock();
            } catch (e) {
              message = formatError(e);
            }
          }}>{$t("keys.ui.disableLock")}</button>
          <button onclick={() => (showLock = false)}>{$t("common.cancel")}</button>
        </div>
      {:else}
        <div class="grid2" style="margin-top: 10px">
          <div>
            <div class="label">{$t("keys.ui.newPassword")}</div>
            <input type="password" bind:value={lockPassword} />
          </div>
          <div>
            <div class="label">{$t("keys.ui.confirmPassword")}</div>
            <input type="password" bind:value={lockPassword2} />
          </div>
        </div>
        <div class="toolbar" style="margin-top: 12px">
          <button class="primary" onclick={async () => {
            try {
              await applyLock();
            } catch (e) {
              message = formatError(e);
            }
          }}>{$t("keys.ui.enableLock")}</button>
          <button onclick={() => (showLock = false)}>{$t("common.cancel")}</button>
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if showPreview}
  <div class="modal" role="presentation">
    <div class="modal-inner" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t("keys.ui.previewTitle")}>
      <div class="modal-title">{$t("keys.ui.previewTitle")}</div>

      {#if !preview}
        <p class="help">{$t("common.loading")}</p>
      {:else}
        <div class="label">{$t("common.name")}</div>
        <div class="value">{preview.label}</div>

        <div class="divider" style="margin: 12px 0"></div>

        {#if preview.kind === "symmetric"}
          <div class="label">{$t("keys.ui.preview.algorithm")}</div>
          <div class="value">{preview.algorithm}</div>

          <div class="toolbar" style="margin-top: 10px">
            <button onclick={() => (previewShowSecret = !previewShowSecret)}>
              {previewShowSecret ? $t("common.hide") : $t("common.show")}
            </button>
          </div>

          {#if previewShowSecret}
            <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.symmetricKey")}</div>
            <textarea rows="5" readonly>{preview.key_b64}</textarea>
          {/if}
        {:else if preview.kind === "rsa"}
          <div class="label">{$t("keys.ui.preview.publicPem")}</div>
          <textarea rows="8" readonly>{preview.public_pem}</textarea>

          {#if preview.private_pem}
            <div class="toolbar" style="margin-top: 10px">
              <button onclick={() => (previewShowSecret = !previewShowSecret)}>
                {previewShowSecret ? $t("common.hide") : $t("common.show")}
              </button>
            </div>
            {#if previewShowSecret}
              <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.privatePem")}</div>
              <textarea rows="10" readonly>{preview.private_pem}</textarea>
            {/if}
          {/if}
        {:else}
          <div class="label">{$t("keys.ui.preview.publicB64")}</div>
          <textarea rows="4" readonly>{preview.public_b64}</textarea>

          <div class="toolbar" style="margin-top: 10px">
            <button onclick={() => (previewShowSecret = !previewShowSecret)}>
              {previewShowSecret ? $t("common.hide") : $t("common.show")}
            </button>
          </div>

          {#if previewShowSecret}
            <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.secretB64")}</div>
            <textarea rows="4" readonly>{preview.secret_b64}</textarea>
          {/if}
        {/if}
      {/if}

      <div class="toolbar" style="margin-top: 12px">
        <button onclick={() => (showPreview = false)}>{$t("common.close")}</button>
      </div>
    </div>
  </div>
{/if}

{#if showExport && exportEntry}
  <div class="modal" role="presentation">
    <div class="modal-inner" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t("keys.ui.exportTitle")}>
      <div class="modal-title">{$t("keys.ui.exportTitle")}</div>

      <div class="label">{$t("common.name")}</div>
      <div class="value">{exportEntry.label}</div>

      <div class="divider" style="margin: 12px 0"></div>

      <div class="label">{$t("keys.ui.exportFormat")}</div>
      <select bind:value={exportFormat}>
        {#each availableExportFormats(exportEntry) as f}
          <option value={f.value}>{f.label}</option>
        {/each}
      </select>

      <div class="toolbar" style="margin-top: 12px">
        <button class="primary" onclick={async () => {
          try {
            await doExport();
          } catch (e) {
            message = formatError(e);
          }
        }}>{$t("keys.ui.saveFile")}</button>
        <button onclick={() => (showExport = false)}>{$t("common.cancel")}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .list {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: rgba(255, 255, 255, 0.55);
    overflow: hidden;
  }

  .table {
    width: 100%;
    border-collapse: collapse;
  }

  .table th,
  .table td {
    border-bottom: 1px solid var(--border);
    padding: 10px 12px;
    font-size: 13px;
    text-align: left;
  }

  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New",
      monospace;
    font-size: 12px;
    color: var(--muted);
  }

  .actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .icon {
    width: 34px;
    height: 34px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .modal {
    position: fixed;
    inset: 0;
    background: rgba(245, 245, 247, 0.92);
    backdrop-filter: blur(10px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .modal-inner {
    width: 100%;
    max-width: 720px;
    padding: 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: rgba(255, 255, 255, 0.75);
  }

  .modal-title {
    font-size: 14px;
    font-weight: 600;
  }

  .label {
    font-size: 12px;
    color: var(--muted);
    margin: 10px 0 6px;
  }

  .value {
    font-size: 13px;
  }
</style>





