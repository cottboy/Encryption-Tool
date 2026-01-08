<!--
  文件加密页（按需求文档落地）：
  - 前端职责：
    1) 展示 UI（算法/密钥选择、文件与输出目录选择）
    2) 调用后端命令启动加密/解密任务（invoke）
    3) 订阅后端事件（progress/done/error/canceled），渲染进度并提供取消按钮

  后端职责（Rust）：
  - 文件加/解密在 Rust 中完成，采用流式分块，避免大文件一次性读入内存。
-->

<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { open } from "@tauri-apps/plugin-dialog";
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

  type KeyPartEncoding = "base64" | "hex" | "pem" | "utf8";

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
    encrypt_needs: string;
    decrypt_needs: string;
    key_parts: AlgorithmKeyPartSpec[];
  };

  let algorithmSpecsById = $state<Record<string, AlgorithmFormSpec>>({});

  type FileCryptoStartResponse = {
    task_id: string;
    output_path: string;
    original_file_name: string | null;
  };

  type FileCryptoProgressEvent = {
    task_id: string;
    stage: "encrypt" | "decrypt";
    processed_bytes: number;
    total_bytes: number;
  };

  type FileCryptoDoneEvent = {
    task_id: string;
    output_path: string;
  };

  type FileCryptoErrorEvent = {
    task_id: string;
    message: string;
  };

  type FileCryptoCanceledEvent = {
    task_id: string;
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

  // 路径输入：
  // - inputPath：待加密/待解密文件路径（前端通过 dialog 选择）
  // - outputDir：输出目录（可空，空表示默认同目录）
  let inputPath = $state<string>("");
  let outputDir = $state<string>("");

  // outputPath：启动任务后由后端推导并返回，用于 UI 展示“将输出到哪里”。
  let outputPath = $state<string>("");

  // 提示信息：用于展示错误、取消提示等。
  let message = $state<string>("");

  // 任务状态：
  // - busy：正在执行任务（用于禁用 UI，避免重复点击）
  // - taskId：当前任务 id（用于过滤事件）
  // - stage：encrypt / decrypt（用于 UI 文案）
  let busy = $state<boolean>(false);
  let taskId = $state<string>("");
  let stage = $state<"" | "encrypt" | "decrypt">("");

  // 进度：
  // - processedBytes / totalBytes：由后端事件更新（明文维度）
  let processedBytes = $state<number>(0);
  let totalBytes = $state<number>(0);

  // 解密任务会返回“将还原的文件名”，这里用于 UI 展示。
  let decryptOriginalName = $state<string>("");


  function isRsaFamily(algo: string): boolean {
    return algo === "RSA-4096";
  }

  function filteredEntries(): KeyEntryPublic[] {
    // 只展示与当前算法匹配的密钥，减少用户选错概率。
    if (!selectedAlgorithm) return [];
    return entries.filter((e) => e.key_type === selectedAlgorithm);
  }

  function canEncryptWithSelectedKey(): boolean {
    const entry = entries.find((e) => e.id === selectedKeyId);
    if (!entry) return false;
    const spec = algorithmSpecsById[selectedAlgorithm];
    if (!spec) return false;

    const required = spec.key_parts.filter((p) => p.required_for_encrypt).map((p) => p.id);
    return required.every((id) => entry.parts_present.includes(id));
  }

  function canDecryptWithSelectedKey(): boolean {
    const entry = entries.find((e) => e.id === selectedKeyId);
    if (!entry) return false;
    const spec = algorithmSpecsById[selectedAlgorithm];
    if (!spec) return false;

    const required = spec.key_parts.filter((p) => p.required_for_decrypt).map((p) => p.id);
    return required.every((id) => entry.parts_present.includes(id));
  }

  function formatBytes(bytes: number): string {
    // 说明：简单的字节格式化，用于进度展示；不追求极致精度。
    if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let v = bytes;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function progressPercent(): number {
    if (!totalBytes || totalBytes <= 0) return 0;
    return Math.min(100, Math.max(0, Math.round((processedBytes / totalBytes) * 100)));
  }

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
    entries = await invoke<KeyEntryPublic[]>("keystore_list_entries");
  }

  async function refreshAll() {
    await refreshAlgorithms();
    await refreshFormSpecs();
    await refreshEntries();
  }

  onMount(() => {
    // 页面加载时刷新一次。
    refreshAll().catch((e) => {
      message = typeof e === "string" ? e : String(e);
    });

    // 监听密钥库变更事件（来自密钥管理页）：例如新增/删除/编辑后需要刷新密钥列表。
    const onKeystoreChanged = () => {
      refreshAll().catch(() => {
        // 忽略：失败时不阻塞 UI。
      });
    };
    window.addEventListener("keystore_status_changed", onKeystoreChanged);

    // 订阅后端事件：进度 / 完成 / 错误 / 取消
    const unlisteners: UnlistenFn[] = [];

    const setup = async () => {
      unlisteners.push(
        await listen<FileCryptoProgressEvent>("file_crypto_progress", (e) => {
          if (!taskId || e.payload.task_id !== taskId) return;
          processedBytes = e.payload.processed_bytes;
          totalBytes = e.payload.total_bytes;
        })
      );

      unlisteners.push(
        await listen<FileCryptoDoneEvent>("file_crypto_done", (e) => {
          if (!taskId || e.payload.task_id !== taskId) return;
          outputPath = e.payload.output_path;
          message = $t("files.ui.msg.done", { path: outputPath });
          busy = false;
          taskId = "";
          stage = "";
        })
      );

      unlisteners.push(
        await listen<FileCryptoErrorEvent>("file_crypto_error", (e) => {
          if (!taskId || e.payload.task_id !== taskId) return;
          message = e.payload.message;
          busy = false;
          taskId = "";
          stage = "";
        })
      );

      unlisteners.push(
        await listen<FileCryptoCanceledEvent>("file_crypto_canceled", (e) => {
          if (!taskId || e.payload.task_id !== taskId) return;
          message = $t("files.ui.msg.canceled");
          busy = false;
          taskId = "";
          stage = "";
        })
      );
    };

    setup().catch(() => {
      // 忽略：事件订阅失败时不阻塞 UI，但进度/取消功能会不可用。
    });

    return () => {
      window.removeEventListener("keystore_status_changed", onKeystoreChanged);
      for (const u of unlisteners) u();
    };
  });

  // =====================
  // 文件/目录选择（dialog 插件）
  // =====================

  async function browseInputFile() {
    if (busy) return;
    message = "";

    const picked = await open({
      multiple: false,
      directory: false
    });

    if (!picked) return;
    inputPath = String(picked);
  }

  async function browseOutputDir() {
    if (busy) return;
    message = "";

    const picked = await open({
      multiple: false,
      directory: true
    });

    if (!picked) return;
    outputDir = String(picked);
  }

  // =====================
  // 启动任务：加密 / 解密 / 取消
  // =====================

  function clearPickedFileAndOutput() {
    /*
      清理“已选择的文件/目录/输出信息”：
      - 用户反馈：点击“取消”后，界面仍然保留已选择的文件路径，观感上像“没有取消成功”。
      - 这里把与本次任务/选择强相关的字段统一清空，避免状态残留影响下一次操作。

      说明：
      - 不清空算法/密钥选择：取消任务≠重置配置；用户通常希望保留算法/密钥快速重试。
    */
    inputPath = "";
    outputDir = "";
    outputPath = "";
    decryptOriginalName = "";
    resetProgress();
  }

  function resetProgress() {
    processedBytes = 0;
    totalBytes = 0;
  }

  async function startEncrypt() {
    if (busy) return;
    message = "";
    outputPath = "";
    decryptOriginalName = "";
    resetProgress();

    if (!selectedAlgorithm) {
      message = $t("files.ui.errors.selectAlgorithm");
      return;
    }
    if (!selectedKeyId) {
      message = $t("files.ui.errors.selectKey");
      return;
    }
    if (!canEncryptWithSelectedKey()) {
      if (selectedAlgorithm === "X25519") {
        message = $t("files.ui.errors.x25519NeedFull");
      } else if (selectedAlgorithm === "ML-KEM-768") {
        message = $t("files.ui.errors.mlkemNeedSession");
      } else if (isRsaFamily(selectedAlgorithm)) {
        message = $t("files.ui.errors.rsaNeedPublic");
      } else {
        message = $t("files.ui.errors.selectKey");
      }
      return;
    }
    if (!inputPath.trim()) {
      message = $t("files.ui.errors.selectFile");
      return;
    }

    busy = true;
    stage = "encrypt";

    try {
      const res = await invoke<FileCryptoStartResponse>("file_encrypt_start", {
        req: {
          algorithm: selectedAlgorithm,
          key_id: selectedKeyId,
          input_path: inputPath,
          output_dir: outputDir.trim() ? outputDir.trim() : null
        }
      });

      taskId = res.task_id;
      outputPath = res.output_path;
      message = $t("files.ui.msg.startedEncrypt", { path: outputPath });
    } catch (e) {
      message = typeof e === "string" ? e : String(e);
      busy = false;
      stage = "";
    }
  }

  async function startDecrypt() {
    if (busy) return;
    message = "";
    outputPath = "";
    decryptOriginalName = "";
    resetProgress();

    if (!selectedAlgorithm) {
      message = $t("files.ui.errors.selectAlgorithm");
      return;
    }
    if (!selectedKeyId) {
      message = $t("files.ui.errors.selectKey");
      return;
    }
    if (!canDecryptWithSelectedKey()) {
      if (selectedAlgorithm === "X25519") {
        message = $t("files.ui.errors.x25519NeedFull");
      } else if (selectedAlgorithm === "ML-KEM-768") {
        message = $t("files.ui.errors.mlkemNeedSession");
      } else if (isRsaFamily(selectedAlgorithm)) {
        message = $t("files.ui.errors.rsaNeedPrivate");
      } else {
        message = $t("files.ui.errors.selectKey");
      }
      return;
    }
    if (!inputPath.trim()) {
      message = $t("files.ui.errors.selectFile");
      return;
    }

    busy = true;
    stage = "decrypt";

    try {
      const res = await invoke<FileCryptoStartResponse>("file_decrypt_start", {
        req: {
          algorithm: selectedAlgorithm,
          key_id: selectedKeyId,
          input_path: inputPath,
          output_dir: outputDir.trim() ? outputDir.trim() : null
        }
      });

      taskId = res.task_id;
      outputPath = res.output_path;
      decryptOriginalName = res.original_file_name ?? "";
      message = decryptOriginalName
        ? $t("files.ui.msg.startedDecryptWithName", { name: decryptOriginalName, path: outputPath })
        : $t("files.ui.msg.startedDecrypt", { path: outputPath });
    } catch (e) {
      message = typeof e === "string" ? e : String(e);
      busy = false;
      stage = "";
    }
  }

  async function cancel() {
    /*
      取消按钮的两种语义（按用户反馈统一体验）：
      1) 正在执行任务：向后端发送取消请求，并清理“已选择文件/输出信息”，避免用户误以为没有取消。
      2) 未执行任务：作为“清空选择”的快捷操作，直接清空已选文件/输出目录/输出提示。
    */
    if (!taskId) {
      clearPickedFileAndOutput();
      message = "";
      return;
    }

    // UI 先即时清空：就算后端取消需要一点时间，用户也能立刻感知“已开始取消”。
    clearPickedFileAndOutput();
    try {
      await invoke("file_crypto_cancel", { taskId });
      message = $t("files.ui.msg.cancelRequested");
    } catch (e) {
      message = typeof e === "string" ? e : String(e);
    }
  }
</script>

<h1 class="h1">{$t("files.title")}</h1>

<div class="divider" style="margin: 14px 0"></div>

<!--
  顶部控制区：对齐“文本加密”页的布局（算法 / 密钥 / 按钮同一行）
  - 桌面端窗口较宽时，一行更符合用户操作习惯。
  - 窗口变窄时允许换行（flex-wrap），避免控件被挤压到难以点击。
-->
<div class="controls" aria-label={$t("files.title")}>
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
      - 与“文本加密”页一致，用户反馈该下拉框在部分环境文字略偏下。
      - 通过单独 class 做 1px 级别的基线微调，确保视觉垂直居中更一致。
    -->
    <select class="key-select" bind:value={selectedKeyId} disabled={busy}>
      <option value="">{$t("common.selectFromKeystore")}</option>
      {#each filteredEntries() as e}
        <option value={e.id}>{e.label}</option>
      {/each}
    </select>
  </div>

  <div class="actions">
    <div class="label" style="opacity: 0">.</div>
    <div class="btn-row">
      <button class="primary" onclick={startEncrypt} disabled={busy}>{$t("common.encrypt")}</button>
      <button onclick={startDecrypt} disabled={busy}>{$t("common.decrypt")}</button>
      <!--
        取消按钮：
        - busy 且 taskId 为空：说明任务还没拿到 id（比如启动请求尚未返回），此时不能取消，避免发空请求。
        - 其它情况允许点击：未启动任务时也可作为“清空选择”使用。
      -->
      <button onclick={cancel} disabled={busy && !taskId}>{$t("common.cancel")}</button>
    </div>
  </div>
</div>

<div style="margin-top: 12px">
  <div class="label">{$t("common.file")}</div>
  <div class="row">
    <input readonly bind:value={inputPath} placeholder={$t("files.ui.placeholders.inputFile")} />
    <button onclick={browseInputFile} disabled={busy}>{$t("common.browse")}</button>
  </div>
</div>

<div style="margin-top: 12px">
  <div class="label">{$t("common.outputDir")}</div>
  <div class="row">
    <input readonly bind:value={outputDir} placeholder={$t("files.ui.placeholders.outputDir")} />
    <button onclick={browseOutputDir} disabled={busy}>{$t("common.browse")}</button>
  </div>
</div>

{#if busy}
  <div style="margin-top: 10px">
    <div class="label">{$t("files.ui.progress.title")}</div>
    <progress max="100" value={progressPercent()} style="width: 100%"></progress>
    <div class="help" style="margin-top: 6px">
      {$t("files.ui.progress.detail", {
        stage: stage === "encrypt" ? $t("files.ui.progress.stageEncrypt") : $t("files.ui.progress.stageDecrypt"),
        percent: progressPercent(),
        processed: formatBytes(processedBytes),
        total: formatBytes(totalBytes)
      })}
    </div>
  </div>
{/if}

{#if outputPath}
  <div class="help" style="margin-top: 10px">{$t("files.ui.msg.outputPath", { path: outputPath })}</div>
{/if}

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
      与“文本加密”页保持一致的宽度策略：
      - 两个下拉框等分剩余空间，避免一个短一个长。
    */
    flex: 1 1 260px;
    min-width: 220px;
  }

  .field select {
    width: 100%;
  }

  /*
    密钥下拉框的“垂直居中”微调：
    - 原因与 text 页相同：不同字体/字形度量下，个别中文文案的基线会显得偏下。
    - 这里保持整体高度不变，仅对内部文字做轻微上移。
  */
  .key-select {
    padding-top: 1px;
    line-height: 37px;
  }

  .actions {
    margin-left: auto;
    /*
      与“文本加密”页对齐：actions 区最小宽度一致，避免 files 页的两个下拉框看起来略短。
      说明：actions 的 min-width 越大，会挤占算法/密钥区域的可用宽度。
    */
    min-width: 200px;
  }

  .btn-row {
    display: flex;
    gap: var(--gap);
    justify-content: flex-end;
    /* 与“文本加密”页一致：按钮不换行，保持同一行对齐更稳定 */
    flex-wrap: nowrap;
  }

  .row {
    display: flex;
    gap: var(--gap);
  }

  .row input {
    flex: 1;
  }
</style>
