/**
 * Trusted Types (CSP `require-trusted-types-for 'script'`): the only script URLs the app creates
 * are its own worker and service worker, and this policy refuses anything else.
 */
interface TrustedTypePolicyLike {
  createScriptURL(url: string): unknown;
}
declare global {
  interface Window {
    trustedTypes?: { createPolicy(name: string, rules: { createScriptURL(u: string): string }): TrustedTypePolicyLike };
  }
}

let policy: TrustedTypePolicyLike | null = null;

export function scriptUrl(url: URL | string): URL {
  const u = new URL(url, location.href);
  if (u.origin !== location.origin) throw new Error("refusing a cross-origin script URL");
  if (window.trustedTypes !== undefined) {
    policy ??= window.trustedTypes.createPolicy("urkey", {
      createScriptURL: (s) => {
        if (new URL(s, location.href).origin !== location.origin) throw new Error("refused");
        return s;
      },
    });
    // The Worker and ServiceWorker constructors accept TrustedScriptURL where a URL is typed.
    return policy.createScriptURL(u.href) as URL;
  }
  return u;
}
