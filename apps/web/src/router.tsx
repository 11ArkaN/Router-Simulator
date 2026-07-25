// Browser route ownership for the static SPA. The topology remains one live
// runtime surface in the first stage, while TanStack Router provides a stable
// boundary for later project, device and capture URLs without coupling C++ to
// navigation state.

import { useEffect } from "react";
import { createRootRoute, createRoute, createRouter,
  type ErrorComponentProps } from "@tanstack/react-router";
import { App } from "./ui/App";

function RecoverRoute({ reset }: ErrorComponentProps) {
  useEffect(() => {
    // Route-level fallback pages expose implementation failures as a second,
    // unrelated interface and discard the topology workspace. Resetting the
    // failed render boundary lets App restore its last durable checkpoint
    // through its normal startup path. Operational failures are handled by
    // App's inline notification state and never reach this boundary.
    reset();
  }, [reset]);
  return null;
}

const rootRoute = createRootRoute({ errorComponent: RecoverRoute });
const labRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: App });
const routeTree = rootRoute.addChildren([labRoute]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register { router: typeof router }
}
