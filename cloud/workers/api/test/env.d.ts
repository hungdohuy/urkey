// Type wiring for tests running inside the Workers runtime.
import type { Env as WorkerEnv } from "../src/env";
import type * as MainModule from "../src/index";

declare global {
  namespace Cloudflare {
    // `env` from "cloudflare:test" uses the Worker's binding types.
    // eslint-disable-next-line @typescript-eslint/no-empty-object-type -- declaration merging
    interface Env extends WorkerEnv {}
    // `exports` from "cloudflare:workers" uses the Worker's main module.
    interface GlobalProps {
      mainModule: typeof MainModule;
    }
  }
}
