// Filters Clarity contract `print` output that the clarinet-sdk-wasm emits
// via `console.log` (from Rust's `uprint!`, routed through wasm-bindgen).
// Loaded via NODE_OPTIONS=--import so it runs before vitest's clarinet
// environment initializes the simnet (which is when the noisy prints fire).
// Set SHOW_CONTRACT_PRINTS=1 to disable.

if (!process.env.SHOW_CONTRACT_PRINTS) {
  // Matches lines ending in ` (contract-name:line)` — the trailing source
  // location clarinet appends to every contract print.
  const printLine = /\s\([a-z0-9-]+:\d+\)\s*$/;
  const origLog = console.log;

  console.log = (...args) => {
    if (args.length === 1 && typeof args[0] === 'string') {
      if (args[0].includes('sbtc-registry:280')) return;
      if (args[0].includes('add-to-allowlist')) return;
      if (args[0].includes('transformMode')) return;
    }
    origLog(...args);
  };
}
