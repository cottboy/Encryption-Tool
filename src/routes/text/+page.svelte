<!--
  文本加密页：
  - 前端职责：
    1) 展示 UI（算法/密钥选择、输入/输出框）
    2) 把参数传给后端 invoke
    3) 展示后端返回的结果/错误
  - 后端职责：
    - 加密/解密在 Rust 中完成（性能与安全都更可控）。

  UI 排版要求（按你的反馈调整）：
  - 顶部一行：算法 / 密钥 / 加密 / 解密
  - 下方：输入框、输出框
-->

<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { t } from "$lib/i18n";

  // =====================
  // 与后端交互的数据结构（保持与 Rust 命令一致）
  // =====================

  type SupportedAlgorithms = {
    symmetric: string[];
    asymmetric: string[];
  };

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

  type TextEncryptResponse = {
    ciphertext: string;
    used_hybrid: boolean;
  };

  type TextDecryptResponse = {
    plaintext: string;
  };

  // =====================
  // 页面状态
  // =====================

  // 密钥库状态：用于判断是否已锁定（锁定时无法列出密钥、也无法加解密）。
  let status = $state<KeyStoreStatus | null>(null);

  // 后端支持的算法列表：用于填充算法下拉框。
  let supportedAlgorithms = $state<string[]>([]);

  // 密钥列表：来自密钥管理页同一个后端接口。
  let entries = $state<KeyEntryPublic[]>([]);

  // UI 选择：算法 + 密钥 id
  let selectedAlgorithm = $state<string>("");
  let selectedKeyId = $state<string>("");

  // 文本输入/输出：
  // - 加密：输入=明文，输出=密文 JSON
  // - 解密：输入=密文 JSON，输出=明文
  let inputText = $state<string>("");
  let outputText = $state<string>("");

  // 提示信息：用于展示后端错误、或 RSA 自动混合加密提示等。
  let message = $state<string>("");

  // 按钮忙碌态：避免重复点击导致并发请求。
  let busy = $state<boolean>(false);

  function isLocked(): boolean {
    return !!status?.encrypted && !status?.unlocked;
  }

  // =====================
  // 初始化：加载算法列表 + 密钥库状态 + 密钥条目
  // =====================

  async function refreshStatus() {
    status = await invoke<KeyStoreStatus>("keystore_status");
  }

  async function refreshAlgorithms() {
    const algos = await invoke<SupportedAlgorithms>("get_supported_algorithms");
    supportedAlgorithms = [...algos.symmetric, ...algos.asymmetric];

    // 默认选择：优先第一个对称算法（更通用），避免页面初次进入为空。
    if (!selectedAlgorithm && supportedAlgorithms.length > 0) {
      selectedAlgorithm = supportedAlgorithms[0];
    }
  }

  async function refreshEntries() {
    // 若密钥库已加密但未解锁，后端会返回明确错误；这里交给 message 展示即可。
    entries = await invoke<KeyEntryPublic[]>("keystore_list_entries");
  }

  function filteredEntries(): KeyEntryPublic[] {
    // 只展示与当前算法匹配的密钥，避免用户选错导致体验混乱。
    if (!selectedAlgorithm) return [];
    return entries.filter((e) => e.key_type === selectedAlgorithm);
  }

  function isRsaFamily(algo: string): boolean {
    return algo === "RSA2048" || algo === "RSA4096";
  }

  // 能力检查：根据算法 + 材料类型决定是否允许加密/解密。
  // - RSA：
  //   - 仅公钥：只能加密
  //   - 仅私钥：只能解密
  //   - 完整：加密+解密
  // - X25519：产品规则要求必须同时具备公钥+私钥才允许加/解密
  function canEncryptWithSelectedKey(): boolean {
    const entry = entries.find((e) => e.id === selectedKeyId);
    if (!entry) return false;

    if (selectedAlgorithm === "X25519") {
      return entry.material_kind === "x25519_full";
    }

    if (isRsaFamily(selectedAlgorithm)) {
      return entry.material_kind === "rsa_public_only" || entry.material_kind === "rsa_full";
    }

    return true;
  }

  function canDecryptWithSelectedKey(): boolean {
    const entry = entries.find((e) => e.id === selectedKeyId);
    if (!entry) return false;

    if (selectedAlgorithm === "X25519") {
      return entry.material_kind === "x25519_full";
    }

    if (isRsaFamily(selectedAlgorithm)) {
      return entry.material_kind === "rsa_private_only" || entry.material_kind === "rsa_full";
    }

    return true;
  }

  function typeSuffix(materialKind: string): string {
    // 复用“密钥管理页”的后缀文案，保证全局一致。
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

  // 选择算法后，清空之前的密钥选择（避免残留不匹配的 id）。
  $effect(() => {
    // 仅在算法确实变化时清空（避免初始化阶段造成反复抖动）。
    if (!selectedAlgorithm) return;
    selectedKeyId = "";
    message = "";
    outputText = "";
  });

  onMount(() => {
    // 页面进入时初始化。
    const init = async () => {
      message = "";
      await refreshStatus();
      await refreshAlgorithms();
      await refreshEntries();
    };

    init().catch((e) => {
      message = typeof e === "string" ? e : String(e);
    });

    // 监听密钥库状态变更（由 layout 或密钥管理页触发）：
    // - 例如：解锁/锁定后，需要刷新密钥列表。
    const handler = () => {
      refreshStatus()
        .then(() => refreshEntries())
        .catch((e) => {
          message = typeof e === "string" ? e : String(e);
        });
    };

    window.addEventListener("keystore_status_changed", handler);
    return () => window.removeEventListener("keystore_status_changed", handler);
  });

  // =====================
  // 加密/解密动作：全部调用后端 Rust 执行
  // =====================

  async function doEncrypt() {
    if (busy) return;
    message = "";
    outputText = "";

    if (isLocked()) {
      message = $t("text.ui.errors.locked");
      return;
    }

    if (!selectedAlgorithm) {
      message = $t("text.ui.errors.selectAlgorithm");
      return;
    }
    if (!selectedKeyId) {
      message = $t("text.ui.errors.selectKey");
      return;
    }
    if (!canEncryptWithSelectedKey()) {
      if (selectedAlgorithm === "X25519") {
        message = $t("text.ui.errors.x25519NeedFull");
      } else if (isRsaFamily(selectedAlgorithm)) {
        message = $t("text.ui.errors.rsaNeedPublic");
      } else {
        message = $t("text.ui.errors.selectKey");
      }
      return;
    }
    if (!inputText.trim()) {
      message = $t("text.ui.errors.inputRequired");
      return;
    }

    busy = true;
    try {
      const res = await invoke<TextEncryptResponse>("text_encrypt", {
        req: {
          algorithm: selectedAlgorithm,
          key_id: selectedKeyId,
          plaintext: inputText
        }
      });

      outputText = res.ciphertext;

      // RSA：明文超长时后端会自动混合加密，这里给一个明确提示。
      if (isRsaFamily(selectedAlgorithm) && res.used_hybrid) {
        message = $t("text.ui.msg.rsaHybrid");
      }
    } catch (e) {
      message = typeof e === "string" ? e : String(e);
    } finally {
      busy = false;
    }
  }

  async function doDecrypt() {
    if (busy) return;
    message = "";
    outputText = "";

    if (isLocked()) {
      message = $t("text.ui.errors.locked");
      return;
    }

    if (!selectedAlgorithm) {
      message = $t("text.ui.errors.selectAlgorithm");
      return;
    }
    if (!selectedKeyId) {
      message = $t("text.ui.errors.selectKey");
      return;
    }
    if (!canDecryptWithSelectedKey()) {
      if (selectedAlgorithm === "X25519") {
        message = $t("text.ui.errors.x25519NeedFull");
      } else if (isRsaFamily(selectedAlgorithm)) {
        message = $t("text.ui.errors.rsaNeedPrivate");
      } else {
        message = $t("text.ui.errors.selectKey");
      }
      return;
    }
    if (!inputText.trim()) {
      message = $t("text.ui.errors.inputRequired");
      return;
    }

    busy = true;
    try {
      const res = await invoke<TextDecryptResponse>("text_decrypt", {
        req: {
          algorithm: selectedAlgorithm,
          key_id: selectedKeyId,
          ciphertext: inputText
        }
      });

      outputText = res.plaintext;
    } catch (e) {
      // 解密失败的核心提示由后端统一收敛：密钥错误或数据已损坏。
      message = typeof e === "string" ? e : String(e);
    } finally {
      busy = false;
    }
  }

  function keyOptionLabel(e: KeyEntryPublic): string {
    // 下拉选项附带“仅公钥/仅私钥/完整”，减少用户选错。
    if (e.material_kind !== "symmetric") {
      return `${e.label} ${typeSuffix(e.material_kind)}`;
    }
    return e.label;
  }
</script>

<h1 class="h1">{$t("text.title")}</h1>
<p class="help">{$t("text.desc")}</p>

<div class="divider" style="margin: 14px 0"></div>

<!--
  顶部控制区：按“算法 / 密钥 / 加密 / 解密”的顺序排列。
  - 这里做成一行 flex：桌面端窗口变宽时不会错位；窗口变窄时允许换行。
-->
<div class="controls" aria-label={$t("text.ui.controls")}>
  <div class="field">
    <div class="label">{$t("common.algorithm")}</div>
    <select bind:value={selectedAlgorithm} disabled={busy || isLocked()}>
      {#each supportedAlgorithms as a}
        <option value={a}>{a}</option>
      {/each}
    </select>
    <div class="help">{$t("text.help.algoMatch")}</div>
  </div>

  <div class="field">
    <div class="label">{$t("common.key")}</div>
    <!--
      密钥选择下拉框：
      - 用户反馈在 Windows WebView2 下，“从密钥库选择/密钥项”的文字基线看起来偏下。
      - 全局 select 已做统一高度/行高，但不同字体的字形度量会导致个别文案仍有轻微偏差。
      - 这里给该下拉框单独加 class，并做 1px 级别的微调，让视觉更接近“垂直居中”。
    -->
    <select class="key-select" bind:value={selectedKeyId} disabled={busy || isLocked()}>
      <option value="">{$t("common.selectFromKeystore")}</option>
      {#each filteredEntries() as e}
        <option value={e.id}>{keyOptionLabel(e)}</option>
      {/each}
    </select>
    <div class="help">{$t("text.help.keyMismatch")}</div>
  </div>

  <div class="actions">
    <div class="label" style="opacity: 0">.</div>
    <div class="btn-row">
      <button class="primary" onclick={doEncrypt} disabled={busy || isLocked()}>{$t("common.encrypt")}</button>
      <button onclick={doDecrypt} disabled={busy || isLocked()}>{$t("common.decrypt")}</button>
    </div>
  </div>
</div>

{#if message}
  <div class="help" style="margin-top: 10px; color: #0b4db8">{message}</div>
{/if}

<div class="io" style="margin-top: 12px">
  <div class="label">{$t("common.input")}</div>
  <textarea bind:value={inputText} rows="8" placeholder={$t("text.ui.placeholders.input")} disabled={busy || isLocked()}></textarea>
</div>

<div class="io" style="margin-top: 12px">
  <div class="label">{$t("common.output")}</div>
  <textarea bind:value={outputText} rows="8" placeholder={$t("text.ui.placeholders.output")} readonly></textarea>
</div>

<style>
  .label {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 6px;
  }

  .controls {
    display: flex;
    gap: var(--gap);
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .field {
    min-width: 220px;
  }

  .field select {
    width: 100%;
  }

  /*
    密钥下拉框的“垂直居中”微调：
    - 仅影响文字的视觉基线，不改变整体控件高度（全局已固定为 40px）。
    - 由于全局开启了 box-sizing: border-box，给 padding-top 1px 不会让控件变高，只会在内部做轻微上移。
  */
  .key-select {
    padding-top: 1px;
    line-height: 37px;
  }

  .actions {
    margin-left: auto;
    min-width: 200px;
  }

  .btn-row {
    display: flex;
    gap: var(--gap);
    justify-content: flex-end;
  }

  .io textarea {
    width: 100%;
  }
</style>
