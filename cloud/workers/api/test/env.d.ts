// Type wiring for tests running inside the Workers runtime.
import type { D1Migration } from "cloudflare:test";
import type { Env as WorkerEnv } from "../src/env";
import type * as MainModule from "../src/index";

declare global {
  namespace Cloudflare {
    // `env` uses the Worker's binding types plus the test-only migrations binding.
    interface Env extends WorkerEnv {
      TEST_MIGRATIONS: D1Migration[];
    }
    // `exports` from "cloudflare:workers" uses the Worker's main module.
    interface GlobalProps {
      mainModule: typeof MainModule;
    }
  }
}
