/** UI-side proxy for the core worker. */
import type { Method, Methods, Notice, Request, Response } from "./protocol";
import { scriptUrl } from "./trusted";
import workerUrl from "./worker.ts?worker&url";

export class CoreError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export interface CoreClient {
  call<M extends Method>(method: M, params: Methods[M]["params"]): Promise<Methods[M]["result"]>;
  subscribe(fn: (n: Notice) => void): () => void;
}

export function createWorkerClient(): CoreClient {
  const worker = new Worker(scriptUrl(workerUrl), { type: "module" });
  let next = 1;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();
  const listeners = new Set<(n: Notice) => void>();
  worker.onmessage = (ev: MessageEvent<Response | Notice>) => {
    const data = ev.data;
    if ("notice" in data) {
      listeners.forEach((fn) => {
        fn(data);
      });
      return;
    }
    const p = pending.get(data.id);
    if (p === undefined) return;
    pending.delete(data.id);
    if (data.ok) p.resolve(data.result);
    else p.reject(new CoreError(data.error));
  };
  return {
    call(method, params) {
      const id = next++;
      const req: Request = { id, method, params };
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
        worker.postMessage(req);
      });
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}
