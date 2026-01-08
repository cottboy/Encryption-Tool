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

  type KeyEntryPublic = {
    id: string;
    label: string;
    key_type: string;
    parts_present: string[];
  };

  // 用于解析算法声明中的编码字段（目前只用于类型约束）。
  type KeyPartEncoding = "base64" | "hex" | "pem" | "utf8";

  // 后端算法声明：用于判断“某个密钥是否满足加/解密必需 parts”。
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

  let algorithmSpecsById = $state<Record<string, AlgorithmFormSpec>>({});

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

  // =====================
  // 初始化：加载算法列表 + 密钥条目
  // =====================

  async function refreshAlgorithms() {
    const algos = await invoke<SupportedAlgorithms>("get_supported_algorithms");
    supportedAlgorithms = [...algos.symmetric, ...algos.asymmetric];

    // 默认选择：优先第一个对称算法（更通用），避免页面初次进入为空。
    if (!selectedAlgorithm && supportedAlgorithms.length > 0) {
      selectedAlgorithm = supportedAlgorithms[0];
    }
  }

  async function refreshFormSpecs() {
    const specs = await invoke<AlgorithmFormSpec[]>("get_algorithm_form_specs");
    const map: Record<string, AlgorithmFormSpec> = {};
    for (const s of specs) map[s.id] = s;
    algorithmSpecsById = map;
  }

  async function refreshEntries() {
    // 密钥列表来自后端：若读取失败，错误会在调用方捕获并展示。
    entries = await invoke<KeyEntryPublic[]>("keystore_list_entries");
  }

  function filteredEntries(): KeyEntryPublic[] {
    // 只展示与当前算法匹配的密钥，避免用户选错导致体验混乱。
    if (!selectedAlgorithm) return [];
    return entries.filter((e) => e.key_type === selectedAlgorithm);
  }

  function isRsaFamily(algo: string): boolean {
    return algo === "RSA-4096";
  }

  function canEncryptWithSelectedKey(): boolean {
    const entry = entries.find((e) => e.id === selectedKeyId);
    if (!entry) return false;
    const spec = algorithmSpecsById[selectedAlgorithm];
    if (!spec) return false;

    // 规则来源：算法文件声明 required_for_encrypt。
    const required = spec.key_parts.filter((p) => p.required_for_encrypt).map((p) => p.id);
    return required.every((id) => entry.parts_present.includes(id));
  }

  function canDecryptWithSelectedKey(): boolean {
    const entry = entries.find((e) => e.id === selectedKeyId);
    if (!entry) return false;
    const spec = algorithmSpecsById[selectedAlgorithm];
    if (!spec) return false;

    // 规则来源：算法文件声明 required_for_decrypt。
    const required = spec.key_parts.filter((p) => p.required_for_decrypt).map((p) => p.id);
    return required.every((id) => entry.parts_present.includes(id));
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
      await refreshAlgorithms();
      await refreshFormSpecs();
      await refreshEntries();
    };

    init().catch((e) => {
      message = typeof e === "string" ? e : String(e);
    });

    // 监听密钥库变更（由密钥管理页触发）：例如新增/删除/编辑后需要刷新密钥列表。
    const handler = () => {
      refreshEntries().catch((e) => {
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
      } else if (selectedAlgorithm === "ML-KEM-768") {
        message = $t("text.ui.errors.mlkemNeedSession");
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
      } else if (selectedAlgorithm === "ML-KEM-768") {
        message = $t("text.ui.errors.mlkemNeedSession");
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

  function clearText() {
    /*
      清空输入/输出：
      - 用户希望一键清理输入框里的内容，方便重新粘贴/重新加解密。
      - 这里同时清空输出与提示信息，避免“上一次结果/提示”残留造成误解。
      - 不清空算法/密钥选择：多数场景是同一算法/同一密钥下反复操作。
    */
    inputText = "";
    outputText = "";
    message = "";
  }

  function keyOptionLabel(e: KeyEntryPublic): string {
    /*
      密钥下拉框的显示文本：
      - 按需求：在“文本加密”页不再在名称后面拼接“完整/仅公钥/仅私钥”等后缀，只展示用户设置的名称。
      - 重要：这里只改“显示”，不改“逻辑”：
        - RSA 加密仍需要公钥、RSA 解密仍需要私钥；
        - X25519 加/解密仍需要同时包含公钥与私钥；
        - 是否可用由 canEncryptWithSelectedKey/canDecryptWithSelectedKey + 后端校验共同保证。
    */
    return e.label;
  }
</script>

<h1 class="h1">{$t("text.title")}</h1>

<div class="divider" style="margin: 14px 0"></div>

<!--
  顶部控制区：按“算法 / 密钥 / 加密 / 解密”的顺序排列。
  - 这里做成一行 flex：桌面端窗口变宽时不会错位；窗口变窄时允许换行。
-->
<div class="controls" aria-label={$t("text.ui.controls")}>
  <div class="field">
    <div class="label">{$t("common.algorithm")}</div>
    <select bind:value={selectedAlgorithm} disabled={busy}>
      {#each supportedAlgorithms as a}
        <option value={a}>{a}</option>
      {/each}
    </select>
  </div>

  <div class="field">
    <div class="label">{$t("common.key")}</div>
    <!--
      密钥选择下拉框：
      - 用户反馈在 Windows WebView2 下，“从密钥库选择/密钥项”的文字基线看起来偏下。
      - 全局 select 已做统一高度/行高，但不同字体的字形度量会导致个别文案仍有轻微偏差。
      - 这里给该下拉框单独加 class，并做 1px 级别的微调，让视觉更接近“垂直居中”。
    -->
    <select class="key-select" bind:value={selectedKeyId} disabled={busy}>
      <option value="">{$t("common.selectFromKeystore")}</option>
      {#each filteredEntries() as e}
        <option value={e.id}>{keyOptionLabel(e)}</option>
      {/each}
    </select>
  </div>

  <div class="actions">
    <div class="label" style="opacity: 0">.</div>
    <div class="btn-row">
      <button class="primary" onclick={doEncrypt} disabled={busy}>{$t("common.encrypt")}</button>
      <button onclick={doDecrypt} disabled={busy}>{$t("common.decrypt")}</button>
      <button onclick={clearText} disabled={busy}>{$t("common.clear")}</button>
    </div>
  </div>
</div>

<div class="io" style="margin-top: 12px">
  <div class="label">{$t("common.input")}</div>
  <textarea bind:value={inputText} rows="8" placeholder={$t("text.ui.placeholders.input")} disabled={busy}></textarea>
</div>

<div class="io" style="margin-top: 12px">
  <div class="label">{$t("common.output")}</div>
  <textarea bind:value={outputText} rows="8" placeholder={$t("text.ui.placeholders.output")} readonly></textarea>
</div>

{#if message}
  <div class="help" style="margin-top: 10px; color: #0b4db8">{message}</div>
{/if}

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
    /*
      控制区两列（算法/密钥）宽度统一：
      - 之前 .field 只设 min-width，在 flex 容器里会按“内容的固有宽度”伸缩，
        导致算法下拉框、密钥下拉框看起来一长一短（尤其是占位文案较长时更明显）。
      - 这里改为可伸缩的等分列：保证两个下拉框在同一行时宽度一致，整体更整齐。
    */
    flex: 1 1 260px;
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
