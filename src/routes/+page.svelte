<!--
  密钥管理（单一 keystore）：
  - 顶部一排按钮：生成密钥 / 导入密钥 / 加密密钥（应用锁）
  - 下方全宽密钥列表：点击任意一行打开“密钥详情”，可编辑/复制
  - 说明：敏感材料始终在后端读取与处理；前端只做展示、输入收集与复制操作
-->

<script lang="ts">
  import { onMount } from "svelte";

  import { invoke } from "@tauri-apps/api/core";

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

  // 密钥详情：用于“点击密钥行 → 弹窗编辑/复制”。
  // 注意：该结构包含敏感材料，前端必须默认隐藏敏感字段，并对显示/复制做二次确认。
  type KeyDetailRaw = {
    id: string;
    label: string;
    key_type: string;
    material_kind: string;

    symmetric_key_b64: string | null;

    rsa_public_pem: string | null;
    rsa_private_pem: string | null;

    x25519_public_b64: string | null;
    x25519_secret_b64: string | null;
  };

  // 弹窗编辑态：为了让 `bind:value` 稳定工作，这里把所有字段都归一化为 string（缺失则置空）。
  type KeyDetail = {
    id: string;
    label: string;
    key_type: string;
    material_kind: string;

    symmetric_key_b64: string;

    rsa_public_pem: string;
    rsa_private_pem: string;

    x25519_public_b64: string;
    x25519_secret_b64: string;
  };

  // 支持的算法列表：
  // - 单一来源：后端 `get_supported_algorithms`（由 Rust 注册表生成）
  // - 这样未来新增算法时，这里不需要再手动改数组，减少漏改风险。
  type SupportedAlgorithms = {
    symmetric: string[];
    asymmetric: string[];
  };
  let supportedTypes = $state<string[]>([]);

  let status = $state<KeyStoreStatus | null>(null);
  let entries = $state<KeyEntryPublic[]>([]);

  let message = $state("");

  // Dialog state
  let showGenerate = $state(false);
  let showImport = $state(false);
  let showLock = $state(false);
  let showDetail = $state(false);

  // 统一处理“关闭弹窗”，用于键盘 ESC。
  function closeTopModal() {
    if (showDetail) {
      showDetail = false;
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
  let genType = $state<string>("AES-256");
  let genLabel = $state("");

  // Import
  let importType = $state<string>("AES-256");
  let importLabel = $state("");
  let importSymmetricKeyB64 = $state("");
  let importRsaPublicPem = $state("");
  let importRsaPrivatePem = $state("");
  let importX25519PublicB64 = $state("");
  let importX25519SecretB64 = $state("");

  // Lock (encrypt keystore)
  let lockPassword = $state("");
  let lockPassword2 = $state("");

  // Detail（点击密钥行打开）
  let detail = $state<KeyDetail | null>(null);

  // 弹窗内提示信息：
  // - 之前 message 渲染在页面底部，弹窗遮罩会挡住，用户会误以为“点确定没反应”。
  // - 因此这里给弹窗单独一份 message，确保可见。
  let modalMessage = $state("");

  // 键盘快捷键：当任意弹窗开启时，按 ESC 关闭。
  $effect(() => {
    const anyOpen = showGenerate || showImport || showLock || showDetail;
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

    // 拉取算法列表（用于“生成/导入”弹窗的下拉框）
    // 注意：即使这里失败，也不影响密钥库读写，只是 UI 下拉框缺少选项。
    try {
      const algos = await invoke<SupportedAlgorithms>("get_supported_algorithms");
      supportedTypes = [...algos.symmetric, ...algos.asymmetric];
    } catch {
      supportedTypes = [];
    }

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

    // 手动导入：前端把用户输入的密钥材料直接传给后端做校验与落库。
    // 注意：对称/非对称的字段不同，这里只传当前类型相关字段，避免混淆。
    await invoke("keystore_import_key_manual", {
      req: buildUpsertPayload(importType, {
        label: name,
        symmetric_key_b64: importSymmetricKeyB64,
        rsa_public_pem: importRsaPublicPem,
        rsa_private_pem: importRsaPrivatePem,
        x25519_public_b64: importX25519PublicB64,
        x25519_secret_b64: importX25519SecretB64
      })
    });

    showImport = false;
    importLabel = "";
    importSymmetricKeyB64 = "";
    importRsaPublicPem = "";
    importRsaPrivatePem = "";
    importX25519PublicB64 = "";
    importX25519SecretB64 = "";
    await refresh();
    notifyKeystoreChanged();
  }

  // =====================
  // 工具函数：类型展示/二次确认/剪贴板复制
  // =====================

  function typeSuffix(materialKind: string): string {
    switch (materialKind) {
      case "rsa_public_only":
        return $t("keys.ui.materialSuffix.rsaPublicOnly");
      case "rsa_private_only":
        return $t("keys.ui.materialSuffix.rsaPrivateOnly");
      case "rsa_full":
        return $t("keys.ui.materialSuffix.rsaFull");
      case "x25519_public_only":
        return $t("keys.ui.materialSuffix.x25519PublicOnly");
      case "x25519_secret_only":
        return $t("keys.ui.materialSuffix.x25519SecretOnly");
      case "x25519_full":
        return $t("keys.ui.materialSuffix.x25519Full");
      default:
        return "";
    }
  }

  function keyTypeDisplay(e: KeyEntryPublic): string {
    // 对称：直接显示算法名；非对称：追加“仅公钥/仅私钥/完整”。
    if (e.material_kind === "symmetric") return e.key_type;
    return `${e.key_type}${typeSuffix(e.material_kind)}`;
  }

  // =====================
  // 密钥详情：打开/编辑/保存
  // =====================

  function resetDetailState() {
    detail = null;
    modalMessage = "";
  }

  async function openDetail(entry: KeyEntryPublic) {
    message = "";
    resetDetailState();
    showDetail = true;

    try {
      const raw = await invoke<KeyDetailRaw>("keystore_get_key_detail", { req: { id: entry.id } });
      detail = {
        ...raw,
        symmetric_key_b64: raw.symmetric_key_b64 ?? "",
        rsa_public_pem: raw.rsa_public_pem ?? "",
        rsa_private_pem: raw.rsa_private_pem ?? "",
        x25519_public_b64: raw.x25519_public_b64 ?? "",
        x25519_secret_b64: raw.x25519_secret_b64 ?? ""
      };
    } catch (e) {
      modalMessage = formatError(e);
      showDetail = false;
    }
  }

  function buildUpsertPayload(tp: string, fields: {
    label: string;
    symmetric_key_b64: string;
    rsa_public_pem: string;
    rsa_private_pem: string;
    x25519_public_b64: string;
    x25519_secret_b64: string;
  }) {
    // 只发送当前类型相关的字段，避免把“旧类型残留字段”误传给后端。
    if (tp === "AES-256" || tp === "ChaCha20") {
      return {
        key_type: tp,
        label: fields.label,
        symmetric_key_b64: fields.symmetric_key_b64,
        rsa_public_pem: null,
        rsa_private_pem: null,
        x25519_public_b64: null,
        x25519_secret_b64: null
      };
    }

    if (tp === "X25519") {
      return {
        key_type: tp,
        label: fields.label,
        symmetric_key_b64: null,
        rsa_public_pem: null,
        rsa_private_pem: null,
        x25519_public_b64: fields.x25519_public_b64,
        x25519_secret_b64: fields.x25519_secret_b64
      };
    }

    // RSA2048 / RSA4096
    return {
      key_type: tp,
      label: fields.label,
      symmetric_key_b64: null,
      rsa_public_pem: fields.rsa_public_pem,
      rsa_private_pem: fields.rsa_private_pem,
      x25519_public_b64: null,
      x25519_secret_b64: null
    };
  }

  async function saveDetail() {
    if (!detail) return;
    modalMessage = "";

    const name = detail.label.trim();
    if (!name) {
      modalMessage = $t("keys.ui.errors.nameRequired");
      return;
    }

    await invoke("keystore_update_key", {
      req: {
        id: detail.id,
        ...buildUpsertPayload(detail.key_type, {
          label: name,
          symmetric_key_b64: detail.symmetric_key_b64,
          rsa_public_pem: detail.rsa_public_pem,
          rsa_private_pem: detail.rsa_private_pem,
          x25519_public_b64: detail.x25519_public_b64,
          x25519_secret_b64: detail.x25519_secret_b64
        })
      }
    });

    showDetail = false;
    await refresh();
    notifyKeystoreChanged();
  }

  // 删除当前详情中的密钥：
  // - 按你的要求：不弹二次确认，直接删除。
  // - 删除失败时，将错误展示在弹窗内。
  async function deleteDetail() {
    if (!detail) return;
    modalMessage = "";

    await invoke("keystore_delete_key", {
      req: {
        id: detail.id
      }
    });

    showDetail = false;
    await refresh();
    notifyKeystoreChanged();
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
</div>

<div class="divider" style="margin: 14px 0"></div>

<div class="list">
  {#if entries.length === 0}
    <!--
      空状态提示：
      - 当密钥库还没有任何条目时，展示引导文案。
      - 这里用单独容器包起来，便于做与表格一致的内边距，让文字不要“贴边”。
    -->
    <div class="list-empty">
      <p class="help">{$t("keys.ui.emptyKeys")}</p>
    </div>
  {:else}
    <table class="table">
      <thead>
        <tr>
          <th style="width: 60%">{$t("common.name")}</th>
          <th style="width: 40%">{$t("common.type")}</th>
        </tr>
      </thead>
      <tbody>
        {#each entries as e}
          <tr class="clickable" onclick={() => openDetail(e)}>
            <!--
              密钥名称列：
              - 这里可能出现用户输入的超长名称。
              - 为避免表格被撑宽产生横向滚动条：UI 采用单行省略号。
              - title 用于悬停查看完整内容（不额外增加布局复杂度）。
            -->
            <td title={e.label}>{e.label}</td>
            <td class="mono">{keyTypeDisplay(e)}</td>
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

      {#if modalMessage}
        <p class="help" style="margin-top: 10px; color: #0b4db8">{modalMessage}</p>
      {/if}
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

      <!--
        手动导入：按算法类型显示不同输入项
        - 对称：只需要密钥（Base64）
        - RSA：公钥/私钥（PEM）可任选其一或同时填写
        - X25519：公钥/私钥（Base64）可任选其一或同时填写
      -->
      {#if importType === "AES-256" || importType === "ChaCha20"}
        <div class="label" style="margin-top: 12px">{$t("keys.ui.preview.symmetricKey")}</div>
        <textarea rows="5" bind:value={importSymmetricKeyB64} placeholder={$t("keys.ui.placeholders.symmetricB64")}></textarea>
      {:else if importType === "X25519"}
        <div class="label" style="margin-top: 12px">{$t("keys.ui.preview.publicB64")}</div>
        <textarea rows="4" bind:value={importX25519PublicB64} placeholder={$t("keys.ui.placeholders.x25519PublicB64")}></textarea>

        <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.secretB64")}</div>
        <textarea rows="4" bind:value={importX25519SecretB64} placeholder={$t("keys.ui.placeholders.x25519SecretB64")}></textarea>

        <div class="help" style="margin-top: 8px">{$t("keys.ui.hints.x25519NeedFull")}</div>
      {:else}
        <div class="label" style="margin-top: 12px">{$t("keys.ui.preview.publicPem")}</div>
        <textarea rows="8" bind:value={importRsaPublicPem} placeholder={$t("keys.ui.placeholders.rsaPublicPem")}></textarea>

        <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.privatePem")}</div>
        <textarea rows="10" bind:value={importRsaPrivatePem} placeholder={$t("keys.ui.placeholders.rsaPrivatePem")}></textarea>
      {/if}

      <div class="toolbar" style="margin-top: 12px">
        <button class="primary" onclick={async () => {
          try {
            modalMessage = "";
            await doImport();
          } catch (e) {
            modalMessage = formatError(e);
          }
        }}>{$t("common.ok")}</button>
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

{#if showDetail}
  <div class="modal" role="presentation">
    <div class="modal-inner" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t("keys.ui.detailTitle")}>
      <div class="modal-title">{$t("keys.ui.detailTitle")}</div>

      {#if modalMessage}
        <p class="help" style="margin-top: 10px; color: #0b4db8">{modalMessage}</p>
      {/if}

      {#if !detail}
        <p class="help">{$t("common.loading")}</p>
      {:else}
        <div class="grid2" style="margin-top: 10px">
          <div>
            <div class="label">{$t("common.algorithm")}</div>
            <select bind:value={detail.key_type}>
              {#each supportedTypes as tp}
                <option value={tp}>{tp}</option>
              {/each}
            </select>
          </div>
          <div>
            <div class="label">{$t("common.name")}</div>
            <input bind:value={detail.label} placeholder="" />
          </div>
        </div>

        <div class="divider" style="margin: 12px 0"></div>

        {#if detail.key_type === "AES-256" || detail.key_type === "ChaCha20"}
          <div class="label">{$t("keys.ui.preview.symmetricKey")}</div>
          <textarea rows="5" bind:value={detail.symmetric_key_b64}></textarea>
        {:else if detail.key_type === "X25519"}
          <div class="label">{$t("keys.ui.preview.publicB64")}</div>
          <textarea rows="4" bind:value={detail.x25519_public_b64}></textarea>

          <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.secretB64")}</div>
          <textarea rows="4" bind:value={detail.x25519_secret_b64}></textarea>

          <div class="help" style="margin-top: 8px">{$t("keys.ui.hints.x25519NeedFull")}</div>
        {:else}
          <div class="label">{$t("keys.ui.preview.publicPem")}</div>
          <textarea rows="8" bind:value={detail.rsa_public_pem}></textarea>

          <div class="label" style="margin-top: 10px">{$t("keys.ui.preview.privatePem")}</div>
          <textarea rows="10" bind:value={detail.rsa_private_pem}></textarea>
        {/if}
      {/if}

      <div class="toolbar toolbar-split" style="margin-top: 12px">
        <div class="toolbar-left">
          <button class="primary" onclick={async () => {
            try {
              modalMessage = "";
              await saveDetail();
            } catch (e) {
              modalMessage = formatError(e);
            }
          }}>{$t("common.ok")}</button>
          <button onclick={() => (showDetail = false)}>{$t("common.cancel")}</button>
        </div>

        <button class="danger" onclick={async () => {
          try {
            modalMessage = "";
            await deleteDetail();
          } catch (e) {
            modalMessage = formatError(e);
          }
        }}>{$t("keys.ui.delete")}</button>
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

    /*
      表格布局控制：
      - table-layout: fixed 可以避免某一列因内容过长而“撑爆”整个表格宽度。
      - 结合 td 的省略号策略，防止出现横向滚动条（尤其在桌面端固定窗口宽度时更明显）。
    */
    table-layout: fixed;
  }

  .table th,
  .table td {
    border-bottom: 1px solid var(--border);
    padding: 10px 12px;
    font-size: 13px;
    text-align: left;
  }

  .table td {
    /* 单行省略号：让超长内容不撑开布局，避免产生横向滚动条 */
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New",
      monospace;
    font-size: 12px;
    color: var(--muted);
  }

  .clickable {
    cursor: pointer;
  }

  .clickable:hover td {
    background: rgba(0, 0, 0, 0.03);
  }

  .list-empty {
    /*
      空状态布局：
      - 目标：与表格单元格（th/td）的左右 padding 对齐，看起来更整齐。
      - 同时去掉 p 的默认 margin，避免出现奇怪的“空隙不一致”。
    */
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .list-empty .help {
    /* 只影响空状态里的 help，避免影响页面其他位置的提示文案 */
    margin: 0;
  }

  textarea {
    width: 100%;
    box-sizing: border-box;
    resize: vertical;
  }

  .danger {
    border-color: rgba(220, 38, 38, 0.35);
    color: rgb(185, 28, 28);
  }

  .danger:hover {
    background: rgba(220, 38, 38, 0.06);
  }

  .toolbar-split {
    width: 100%;
    justify-content: space-between;
  }

  .toolbar-left {
    display: flex;
    gap: var(--gap);
    align-items: center;
    flex-wrap: wrap;
  }

  .modal {
    position: fixed;
    inset: 0;
    background: rgba(245, 245, 247, 0.92);
    backdrop-filter: blur(10px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 12px;
  }

  .modal-inner {
    /*
      弹窗尺寸策略：
      - 之前使用固定 max-width，窗口较小时容易被裁切。
      - 这里改为按“当前可视区域百分比”铺开，同时限制高度并允许滚动。
    */
    width: 92vw;
    height: 90vh;
    max-width: 92vw;
    max-height: 90vh;
    overflow: auto;
    padding: 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: rgba(255, 255, 255, 0.75);
    box-sizing: border-box;
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
</style>





