// Public contracts for the current multi-device product boundary. Previous
// project, runtime and manifest types are intentionally absent so application
// code cannot accidentally restore the removed single-router architecture.

export { LAB_RUNTIME_PROTOCOL } from "./generated-lab-runtime-protocol";
export {
  LAB_BUILD_HASH,
  PROFILE_CATALOG,
  PROFILE_CATALOG_COMPILED,
  PROFILE_CATALOG_HASH
} from "./generated-device-catalog";
export * from "./lab-project-v3";
export * from "./reference-lab-v3";
export * from "./lab-runtime-v5";
export * from "./terminal-presentation-v2";
