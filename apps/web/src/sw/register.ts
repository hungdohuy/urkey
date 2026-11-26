/** Registers the pinning service worker in production and reports updates waiting for approval. */
import { scriptUrl } from "../core/trusted";

export interface UpdateInfo {
  release: string;
  activate: () => void;
}

export function registerServiceWorker(onUpdate: (u: UpdateInfo) => void): void {
  if (!import.meta.env.PROD || !("serviceWorker" in navigator)) return;
  let approved = false;
  void navigator.serviceWorker.register(scriptUrl("/sw.js"), { scope: "/" }).then((reg) => {
    const announce = async (worker: ServiceWorker) => {
      let release = "unknown";
      try {
        release = ((await (await fetch("/release.json", { cache: "no-store" })).json()) as { hash: string }).hash;
      } catch {
        /* offline */
      }
      onUpdate({
        release,
        activate: () => {
          approved = true;
          worker.postMessage("activate-update");
        },
      });
    };
    if (reg.waiting !== null && navigator.serviceWorker.controller !== null) void announce(reg.waiting);
    reg.addEventListener("updatefound", () => {
      const next = reg.installing;
      next?.addEventListener("statechange", () => {
        // Only a *changed* release (an existing controller) needs approval; the first install doesn't.
        if (next.state === "installed" && navigator.serviceWorker.controller !== null) void announce(next);
      });
    });
    // Reload only after the user approved an update (the first install also changes controller).
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (approved) location.reload();
    });
  });
}

/** The release hash of the running (pinned) bundle, from the active service worker. */
export function installedRelease(): Promise<string> {
  return new Promise((resolve) => {
    const controller = "serviceWorker" in navigator ? navigator.serviceWorker.controller : null;
    if (!import.meta.env.PROD || controller == null) {
      resolve(import.meta.env.PROD ? "not installed yet" : "development build");
      return;
    }
    const onMessage = (e: MessageEvent<{ release?: string }>) => {
      if (typeof e.data.release === "string") {
        navigator.serviceWorker.removeEventListener("message", onMessage);
        resolve(e.data.release);
      }
    };
    navigator.serviceWorker.addEventListener("message", onMessage);
    controller.postMessage("release");
  });
}
