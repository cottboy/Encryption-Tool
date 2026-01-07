/*
  i18n 模块（翻译文件接口）：
  - 需求要求：不能把语言切换写死在代码里，必须从外部翻译文件加载。
  - 这里把翻译文件放在 `static/locales/*.json`，运行时通过 `fetch` 读取。
  - 后续新增语言：只需新增一个 JSON 文件，并把 `supportedLocales` 增加一项即可。

  使用方式（Svelte）：
  - `import { t, setLocale, locale } from "$lib/i18n"`
  - 文案：`{$t("app.tabs.keys")}`
*/

import { derived, type Readable, writable } from "svelte/store";

// 翻译文件的数据结构：允许任意 JSON（对象树），通过 keyPath 递归读取。
export type LocaleMessages = Record<string, unknown>;

// 支持的语言列表：与 `static/locales` 下的文件对应。
export const supportedLocales = ["zh-CN", "en-US"] as const;
export type SupportedLocale = (typeof supportedLocales)[number];

// 默认语言：当系统语言无法匹配时使用。
const defaultLocale: SupportedLocale = "zh-CN";

function normalizeLocaleTag(tag: string): string {
  return tag.trim().replace("_", "-");
}

// 根据系统语言（WebView/浏览器）选择初始语言。
function getSystemLocale(): SupportedLocale {
  const candidates: string[] = [];

  if (typeof navigator !== "undefined") {
    if (Array.isArray(navigator.languages)) candidates.push(...navigator.languages);
    if (navigator.language) candidates.push(navigator.language);
  }

  const normalized = candidates.map(normalizeLocaleTag).filter(Boolean);

  // 1) 先尝试精确匹配（例如 en-US / zh-CN）。
  for (const tag of normalized) {
    if ((supportedLocales as readonly string[]).includes(tag)) return tag as SupportedLocale;
  }

  // 2) 再按“主语言”兜底匹配（例如 zh-Hans / en-GB）。
  for (const tag of normalized) {
    const primary = tag.split("-")[0]?.toLowerCase();
    if (primary === "zh") return "zh-CN";
    if (primary === "en") return "en-US";
  }

  return defaultLocale;
}

// 当前语言 store：UI 订阅后可实时响应切换。
export const locale = writable<SupportedLocale>(defaultLocale);

// 当前语言翻译内容 store。
const messages = writable<LocaleMessages>({});

// 从静态资源目录加载翻译文件。
async function loadMessages(next: SupportedLocale): Promise<LocaleMessages> {
  const resp = await fetch(`/locales/${next}.json`, { cache: "no-cache" });
  if (!resp.ok) {
    throw new Error(`无法加载翻译文件：/locales/${next}.json`);
  }
  return (await resp.json()) as LocaleMessages;
}

// 设置语言：加载翻译、更新状态。
export async function setLocale(next: SupportedLocale): Promise<void> {
  const data = await loadMessages(next);
  messages.set(data);
  locale.set(next);

  try {
    document.documentElement.lang = next;
  } catch {
    // 某些 WebView 环境可能限制对 document 的访问，失败则忽略。
  }
}

// 根据 keyPath（例如 "app.tabs.keys"）读取翻译字符串。
function getByPath(obj: unknown, keyPath: string): string | undefined {
  if (!obj || typeof obj !== "object") return undefined;

  const parts = keyPath.split(".").filter(Boolean);
  let cursor: unknown = obj;

  for (const part of parts) {
    if (!cursor || typeof cursor !== "object") return undefined;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    cursor = (cursor as any)[part];
  }

  return typeof cursor === "string" ? cursor : undefined;
}

// 简单插值：支持 "Hello {name}" 这种模板。
function format(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, k: string) => {
    const v = vars[k];
    return v === undefined ? `{${k}}` : String(v);
  });
}

// 导出翻译函数 store：组件里用 `$t(key)` 获取文案。
export const t: Readable<(key: string, vars?: Record<string, string | number>) => string> = derived(
  [messages],
  ([$messages]) => {
    return (key: string, vars?: Record<string, string | number>) => {
      const v = getByPath($messages, key);
      if (v) return format(v, vars);
      // 缺失翻译时返回 key，方便开发定位。
      return key;
    };
  }
);

// 模块初始化：启动时按系统语言自动选择（匹配不到则用默认语言）。
(async () => {
  const initial = getSystemLocale();
  try {
    await setLocale(initial);
  } catch {
    await setLocale(defaultLocale);
  }
})();
