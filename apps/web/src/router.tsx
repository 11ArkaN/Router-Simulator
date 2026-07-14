// Browser route ownership for the static SPA. The topology remains one live
// runtime surface in the first stage, while TanStack Router provides a stable
// boundary for later project, device and capture URLs without coupling C++ to
// navigation state.

import { createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { App } from "./ui/App";

const rootRoute = createRootRoute();
const labRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: App });
const routeTree = rootRoute.addChildren([labRoute]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register { router: typeof router }
}
