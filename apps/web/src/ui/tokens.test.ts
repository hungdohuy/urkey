// @vitest-environment node
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const css = readFileSync(new URL("./tokens.css", import.meta.url), "utf8");

/** WCAG 2.2 relative luminance and contrast ratio for #rrggbb colours. */
function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)) as [
    number,
    number,
    number,
  ];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** Collects `--name: #hex` declarations from one CSS block. */
function tokens(block: string): Map<string, string> {
  return new Map([...block.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1] ?? "", m[2] ?? ""]));
}

const light = tokens(css.slice(0, css.indexOf("@media")));
const darkStart = css.indexOf(':root[data-theme="dark"]');
const dark = tokens(css.slice(darkStart, css.indexOf("}", darkStart)));

const PAIRS: [fg: string, bg: string, min: number][] = [
  ["text-1", "surface-0", 4.5],
  ["text-1", "surface-1", 4.5],
  ["text-2", "surface-0", 4.5],
  ["text-2", "surface-1", 4.5],
  ["text-3", "surface-1", 4.5],
  ["accent-text", "accent", 4.5],
  ["accent", "surface-1", 4.5],
  ["ok", "ok-bg", 4.5],
  ["warn", "warn-bg", 4.5],
  ["danger", "danger-bg", 4.5],
  ["info", "info-bg", 4.5],
];

describe.each([
  ["light", light],
  ["dark", dark],
])("%s theme contrast (WCAG AA)", (_name, theme) => {
  it.each(PAIRS)("--%s on --%s ≥ %d:1", (fg, bg, min) => {
    const f = theme.get(fg);
    const b = theme.get(bg);
    expect(f, fg).toBeDefined();
    expect(b, bg).toBeDefined();
    expect(contrast(f ?? "", b ?? "")).toBeGreaterThanOrEqual(min);
  });
});
