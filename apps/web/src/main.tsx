import ReactDOM from "react-dom/client";
import { RouterProvider } from "@tanstack/react-router";
import "@xyflow/react/dist/style.css";
import "@xterm/xterm/css/xterm.css";
import "./styles.css";
import { router } from "./router";

// xterm owns imperative DOM state and WebAssembly owns long-lived pthreads.
// A development-only double mount would create and destroy both resources in
// the same frame, which is not a lifecycle the production application uses.
ReactDOM.createRoot(document.getElementById("root")!).render(<RouterProvider router={router} />);
