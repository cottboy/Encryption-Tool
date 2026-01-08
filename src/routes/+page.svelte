<!--
  密钥管理（单一 keystore）：
  - 顶部一排按钮：生成密钥 / 导入密钥
  - 下方全宽密钥列表：点击任意一行打开“密钥详情”，可编辑/复制
  - 说明：敏感材料始终在后端读取与处理；前端只做展示、输入收集与复制操作
-->

<script lang="ts">
  import { onMount } from "svelte";

  import { invoke } from "@tauri-apps/api/core";

  import { t } from "$lib/i18n";

  type KeyStoreStatus = {
    exists: boolean;
    key_count: number | null;
  };

  type KeyEntryPublic = {
    id: string;
    label: string;
    key_type: string;
    parts_present: string[];
  };

  // 通用 parts 结构：与后端 KeyPart 对齐（用于导入/编辑/展示）。
  type KeyPartEncoding = "base64" | "hex" | "pem" | "utf8";
  type KeyPart = {
    id: string;
    encoding: KeyPartEncoding;
    value: string;
  };

  // 密钥详情：用于“点击密钥行 → 弹窗编辑/复制”。
  // 注意：该结构包含敏感材料，前端必须默认隐藏敏感字段，并对显示/复制做二次确认。
  type KeyDetailRaw = {
    id: string;
    label: string;
    key_type: string;
    parts: KeyPart[];
  };

  // 弹窗编辑态：为了让输入框稳定工作，这里把 parts 转成 “id -> value” 映射（缺失则视为空）。
  type KeyDetail = {
    id: string;
    label: string;
    key_type: string;
    parts: Record<string, string>;
  };

  // 支持的算法列表：
  // - 单一来源：后端 `get_supported_algorithms`（由 Rust 注册表生成）
  // - 这样未来新增算法时，这里不需要再手动改数组，减少漏改风险。
  type SupportedAlgorithms = {
    symmetric: string[];
    asymmetric: string[];
  };
  let supportedTypes = $state<string[]>([]);

  // 后端算法声明（用于“按声明动态渲染输入表单”）
  type AlgorithmKeyPartSpec = {
    id: string;
    encoding: KeyPartEncoding;
    hidden: boolean;
    label_key: string;
    placeholder_key: string | null;
    rows: number;
    hint_key: string | null;
    required_for_encrypt: boolean;
    required_for_decrypt: boolean;
  };

  type AlgorithmFormSpec = {
    id: string;
    category: "symmetric" | "asymmetric";
    encrypt_needs_key: string;
    decrypt_needs_key: string;
    key_parts: AlgorithmKeyPartSpec[];
  };

  // 按算法 id 建索引，方便快速查找当前算法需要哪些字段。
  let algorithmSpecsById = $state<Record<string, AlgorithmFormSpec>>({});

  let status = $state<KeyStoreStatus | null>(null);
  let entries = $state<KeyEntryPublic[]>([]);

  let message = $state("");

  // Dialog state
  let showGenerate = $state(false);
  let showImport = $state(false);
  let showDetail = $state(false);

  // 统一处理“关闭弹窗”，用于键盘 ESC。
  function closeTopModal() {
    if (showDetail) {
      showDetail = false;
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
  // 导入弹窗的 parts 输入（id -> value）。
  let importParts = $state<Record<string, string>>({});

  // 当导入弹窗开启且算法切换时，清空输入：
  // - 避免把上一个算法的输入残留误认为“当前算法的字段”。
  $effect(() => {
    if (!showImport) return;
    // 显式依赖 importType：只有算法变化才重置。
    importType;
    importParts = {};
  });

  // Detail（点击密钥行打开）
  let detail = $state<KeyDetail | null>(null);

  type MlKem768GenerateEncapsulationResponse = {
    ct_b64: string;
  };

  // 弹窗内提示信息：
  // - 之前 message 渲染在页面底部，弹窗遮罩会挡住，用户会误以为“点确定没反应”。
  // - 因此这里给弹窗单独一份 message，确保可见。
  let modalMessage = $state("");

  // 键盘快捷键：当任意弹窗开启时，按 ESC 关闭。
  $effect(() => {
    const anyOpen = showGenerate || showImport || showDetail;
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

    // 拉取算法表单声明：用于动态生成“导入/编辑”输入项。
    // 注意：即使这里失败，也不会影响密钥库读写；只是 UI 会退回到“无字段”状态。
    try {
      const specs = await invoke<AlgorithmFormSpec[]>("get_algorithm_form_specs");
      const map: Record<string, AlgorithmFormSpec> = {};
      for (const s of specs) map[s.id] = s;
      algorithmSpecsById = map;
    } catch {
      algorithmSpecsById = {};
    }

    try {
      entries = await invoke<KeyEntryPublic[]>("keystore_list_entries");
    } catch {
      entries = [];
    }
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

    await invoke("keystore_import_key_manual", {
      req: buildUpsertPayload(importType, name, importParts)
    });

    showImport = false;
    importLabel = "";
    importParts = {};
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

  function materialKindFromParts(keyType: string, partsPresent: string[]): string {
    const has = (id: string) => partsPresent.includes(id);

    // 对称：不需要区分“仅公钥/仅私钥/完整”。
    if (keyType === "AES-256" || keyType === "ChaCha20") return "symmetric";

    // RSA：公钥/私钥任意存在都允许存，但加/解密能力由其他页面/按钮控制。
    if (keyType === "RSA-4096") {
      const pub = has("rsa_public_pem");
      const priv = has("rsa_private_pem");
      if (pub && priv) return "rsa_full";
      if (pub) return "rsa_public_only";
      return "rsa_private_only";
    }

    // X25519：同样区分公钥/私钥/完整（产品规则：加/解密必须完整）。
    if (keyType === "X25519") {
      const pub = has("x25519_public_b64");
      const sec = has("x25519_secret_b64");
      if (pub && sec) return "x25519_full";
      if (pub) return "x25519_public_only";
      return "x25519_secret_only";
    }

    return "";
  }

  function keyTypeDisplay(e: KeyEntryPublic): string {
    const kind = materialKindFromParts(e.key_type, e.parts_present);
    if (kind === "symmetric") return e.key_type;
    return `${e.key_type}${typeSuffix(kind)}`;
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
      const map: Record<string, string> = {};
      for (const p of raw.parts) {
        map[p.id] = p.value ?? "";
      }
      detail = {
        id: raw.id,
        label: raw.label,
        key_type: raw.key_type,
        parts: map
      };
    } catch (e) {
      modalMessage = formatError(e);
      showDetail = false;
    }
  }

  async function reloadDetail(id: string) {
    const raw = await invoke<KeyDetailRaw>("keystore_get_key_detail", { req: { id } });
    const map: Record<string, string> = {};
    for (const p of raw.parts) {
      map[p.id] = p.value ?? "";
    }
    detail = {
      id: raw.id,
      label: raw.label,
      key_type: raw.key_type,
      parts: map
    };
  }

  function buildUpsertPayload(tp: string, label: string, partValues: Record<string, string>) {
    // 这里严格按“后端算法声明（AlgorithmFormSpec）”生成 parts：
    // - 避免把不属于当前算法的字段误传给后端；
    // - 同时让新增算法只改算法文件，不改前端保存逻辑。
    const spec = algorithmSpecsById[tp];
    if (!spec) {
      throw new Error($t("common.loading"));
    }

    const parts: KeyPart[] = [];
    for (const p of spec.key_parts) {
      const v = (partValues[p.id] ?? "").trim();
      if (!v) continue;
      parts.push({ id: p.id, encoding: p.encoding, value: v });
    }

    return {
      key_type: tp,
      label,
      parts
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
        ...buildUpsertPayload(detail.key_type, name, detail.parts)
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
          <div class="label">{$t("common.name")}</div>
          <input bind:value={importLabel} placeholder="" />
        </div>
      </div>

      <!--
        手动导入：按“后端算法声明（AlgorithmFormSpec）”动态生成输入项。

        说明：
        - 这里不再按算法写死 if/else（避免新增算法时必须改前端模板）
        - 仍然受限于当前后端 UpsertKeyRequest 的固定字段集合，因此支持的 field 也是固定集合
      -->
      {#if algorithmSpecsById[importType]}
        {@const importSpec = algorithmSpecsById[importType]}
        {#each importSpec.key_parts as p (p.id)}
          {#if !p.hidden}
            <div class="label" style="margin-top: 12px">{$t(p.label_key)}</div>
            <textarea
              rows={p.rows}
              value={importParts[p.id] ?? ""}
              placeholder={p.placeholder_key ? $t(p.placeholder_key) : ""}
              oninput={(e) => {
                importParts[p.id] = (e.target as HTMLTextAreaElement).value;
              }}
            ></textarea>

            {#if p.hint_key}
              <div class="help" style="margin-top: 8px">{$t(p.hint_key)}</div>
            {/if}
          {/if}
        {/each}
      {:else}
        <p class="help" style="margin-top: 12px">{$t("common.loading")}</p>
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

      {#if algorithmSpecsById[detail.key_type]}
          {@const detailSpec = algorithmSpecsById[detail.key_type]}
          {#each detailSpec.key_parts as p (p.id)}
            {#if !p.hidden}
              <div class="label" style="margin-top: 12px">{$t(p.label_key)}</div>
              <textarea
                rows={p.rows}
                value={detail.parts[p.id] ?? ""}
                placeholder={p.placeholder_key ? $t(p.placeholder_key) : ""}
                oninput={(e) => {
                  // 防御：这里理论上 detail 一定存在（外层已判断），但 TS 无法在回调里做窄化。
                  if (!detail) return;
                  detail.parts[p.id] = (e.target as HTMLTextAreaElement).value;
                }}
              ></textarea>

              {#if p.hint_key}
                <div class="help" style="margin-top: 8px">{$t(p.hint_key)}</div>
              {/if}
            {/if}
          {/each}
        {:else}
          <p class="help">{$t("common.loading")}</p>
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

          {#if detail && detail.key_type === "ML-KEM-768"}
            <button onclick={async () => {
              try {
                modalMessage = "";
                if (!detail) return;
                const id = detail.id;
                const res = await invoke<MlKem768GenerateEncapsulationResponse>("mlkem768_generate_encapsulation", {
                  req: { id }
                });
                // 更新本地展示（封装密钥），并重新拉取详情，确保隐藏的共享密钥也被保留。
                detail.parts["mlkem768_ct_b64"] = res.ct_b64;
                await reloadDetail(id);
                await refresh();
                notifyKeystoreChanged();
              } catch (e) {
                modalMessage = formatError(e);
              }
            }}>{$t("keys.ui.generateEncapsulation")}</button>
          {/if}
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

  /* 让“算法下拉框”和“名称输入框”在 grid2 中等宽展示（对齐两列视觉长度）。 */
  .grid2 select,
  .grid2 input {
    width: 100%;
    box-sizing: border-box;
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





