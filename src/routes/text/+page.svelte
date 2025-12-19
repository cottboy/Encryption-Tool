<!--
  文本加密页（占位）：
  - 后续会调用 Rust 后端执行加解密，前端只负责收集参数与展示结果。
  - RSA 有明文长度限制：超长会自动使用“混合加密”（RSA 包裹会话密钥）。
  - X25519 天然走“混合加密”（协商会话密钥，再用对称算法处理正文）。

  UI 风格：
  - 扁平化，不使用卡片堆叠。
-->

<script lang="ts">
  import { t } from "$lib/i18n";
</script>

<h1 class="h1">{$t("text.title")}</h1>
<p class="help">{$t("text.desc")}</p>

<div class="divider" style="margin: 14px 0"></div>

<div class="grid2">
  <div>
    <div class="label">{$t("common.algorithm")}</div>
    <select disabled>
      <option>AES-256</option>
      <option>ChaCha20</option>
      <option>RSA（超长自动混合）</option>
      <option>X25519（混合加密）</option>
    </select>
    <div class="help">{$t("text.help.algoMatch")}</div>
  </div>

  <div>
    <div class="label">{$t("common.key")}</div>
    <select disabled>
      <option>{$t("common.selectFromKeystore")}</option>
    </select>
    <div class="help">{$t("text.help.keyMismatch")}</div>
  </div>
</div>

<div style="margin-top: 12px">
  <div class="label">{$t("common.input")}</div>
  <textarea disabled rows="8" placeholder={$t("common.notImplemented")}></textarea>
</div>

<div style="margin-top: 12px">
  <div class="label">{$t("common.output")}</div>
  <textarea disabled rows="8" placeholder={$t("common.notImplemented")}></textarea>
</div>

<div class="toolbar" style="margin-top: 12px">
  <button class="primary" disabled>{$t("common.encrypt")}</button>
  <button disabled>{$t("common.decrypt")}</button>
</div>

<style>
  .label {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 6px;
  }
</style>
