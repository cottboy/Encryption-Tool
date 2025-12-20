<!--
  文件加密页（占位）：
  - 需求要求：必须支持大文件“流式分块加密/解密”。
  - 输出扩展名统一为 .encrypted。
  - 加密文件内部需保存原始文件名/扩展名，以便解密时还原。
  - RSA/X25519 在文件场景一律走混合加密（只包裹会话密钥，数据仍用对称流式处理）。

  UI 风格：
  - 扁平化，不使用卡片堆叠。
-->

<script lang="ts">
  import { t } from "$lib/i18n";
</script>

<h1 class="h1">{$t("files.title")}</h1>
<p class="help">{$t("files.desc")}</p>

<div class="divider" style="margin: 14px 0"></div>

<div class="grid2">
  <div>
    <div class="label">{$t("common.algorithm")}</div>
    <select disabled>
      <option>AES-256（流式）</option>
      <option>ChaCha20（流式）</option>
      <option>RSA2048（混合加密 + 流式）</option>
      <option>RSA4096（混合加密 + 流式）</option>
      <option>X25519（混合加密 + 流式）</option>
    </select>
  </div>

  <div>
    <div class="label">{$t("common.key")}</div>
    <select disabled>
      <option>{$t("common.selectFromKeystore")}</option>
    </select>
  </div>
</div>

<div style="margin-top: 12px">
  <div class="label">{$t("common.file")}</div>
  <div class="row">
    <input disabled placeholder={$t("common.notImplemented")} />
    <button disabled>{$t("common.browse")}</button>
  </div>
</div>

<div style="margin-top: 12px">
  <div class="label">{$t("common.outputDir")}</div>
  <div class="row">
    <input disabled placeholder={$t("common.notImplemented")} />
    <button disabled>{$t("common.browse")}</button>
  </div>
  <div class="help">{$t("files.help.outputExt")}</div>
</div>

<div class="toolbar" style="margin-top: 12px">
  <button class="primary" disabled>{$t("common.encrypt")}</button>
  <button disabled>{$t("common.decrypt")}</button>
  <button disabled>{$t("common.cancel")}</button>
</div>

<div class="help" style="margin-top: 10px">{$t("files.help.progress")}</div>

<style>
  .label {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 6px;
  }

  .row {
    display: flex;
    gap: var(--gap);
  }

  .row input {
    flex: 1;
  }
</style>
