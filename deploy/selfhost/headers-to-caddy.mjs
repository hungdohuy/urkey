// Converts the web build's `_headers` file (Cloudflare format) into Caddy `header` directives,
// so self-hosted and Cloudflare-hosted apps send exactly the same security headers (ADR 0018).
// Usage: node headers-to-caddy.mjs <_headers> <out.caddy>
import { readFileSync, writeFileSync } from "node:fs";

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error("usage: headers-to-caddy.mjs <_headers> <out.caddy>");
const blocks = [];
for (const line of readFileSync(input, "utf8").split("\n")) {
  if (line.trim() === "" || line.trim().startsWith("#")) continue;
  if (!/^\s/.test(line)) {
    blocks.push({ path: line.trim(), headers: [] });
    continue;
  }
  const i = line.indexOf(":");
  if (i < 0 || blocks.length === 0) throw new Error(`bad _headers line: ${line}`);
  blocks.at(-1).headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
}
const quote = (v) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const out = ["# Generated from the web build's _headers by headers-to-caddy.mjs. Do not edit."];
blocks.forEach((b, n) => {
  const lines = b.headers.map(([k, v]) => `\t${k} ${quote(v)}`);
  if (b.path === "/*") {
    out.push("header {", ...lines, "}");
  } else {
    out.push(`@h${n} path ${b.path}`, `header @h${n} {`, ...lines, "}");
  }
});
writeFileSync(output, out.join("\n") + "\n");
