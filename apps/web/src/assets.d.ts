// Compile-time declarations for non-code assets imported through Vite. This
// module owns types only and must never perform runtime loading or validation.

declare module "*.netsim?raw" {
  const manifestText: string;
  export default manifestText;
}
