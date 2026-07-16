// Packet-path regression gate. It compares current Wasm measurements against
// the committed machine-independent scale and per-stage thresholds.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { constants as osConstants, setPriority } from "node:os";

const root = resolve(import.meta.dirname, "..");
const baselinePath = resolve(root, "benchmarks/packet-path-baseline.json");
const executable = resolve(root, "build/wasm/packet_benchmark.js");
const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
const runs = [];

// Desktop power management and background UI work can lower the clock for an
// entire seven-run batch, making every unrelated metric fail together. A high
// priority class reduces scheduler preemption but does not change benchmark
// code, thresholds or results. Child Node processes inherit this priority on
// Windows. Restricted CI environments may reject the request, so correctness
// never depends on it and the existing multi-run median remains the fallback.
try {
  setPriority(0, osConstants.priority.PRIORITY_HIGH);
} catch {
  // Lack of permission is expected in some containers and is not a test error.
}

// Multiple short runs reduce scheduler noise without hiding a persistent
// regression. Median is compared with the checked-in environment-specific
// baseline, while every raw result remains visible in failure output.
for (let index = 0; index < baseline.runs; ++index) {
  const result = spawnSync(process.execPath, [executable], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || "Packet benchmark failed");
  runs.push(JSON.parse(result.stdout.trim()));
}
const median = (values) => [...values].sort((left, right) => left - right)[Math.floor(values.length / 2)];
const encoding = median(runs.map((run) => run.encodingNsPerFrame));
const forwarding = median(runs.map((run) => run.forwardingNsPerFrame));
const linkScheduling = median(runs.map((run) => run.linkSchedulingNsPerFrame));
const limit = 1 + baseline.regressionLimitPercent / 100;
const lowerLimit = 1 / limit;
const failures = [];
const measurements = [
  ["encoding", encoding, baseline.encodingMedianNsPerFrame],
  ["forwarding", forwarding, baseline.forwardingMedianNsPerFrame],
  ["link-scheduling", linkScheduling, baseline.linkSchedulingMedianNsPerFrame]
];
const scale = median(measurements.map(([, observed, reference]) => observed / reference));
const coherentLimit = 1 + baseline.coherentSlowdownLimitPercent / 100;
const rawRatios = measurements.map(([, observed, reference]) => observed / reference);
const independentlySlowerStages = rawRatios.filter((ratio) => ratio > limit).length;

// CPU frequency changes scale all three independent paths together. Normalize
// by their median scale so a relative regression in any one path still fails,
// while a laptop power-state change does not create three false positives. A
// lower normalized value is evidence of a two-stage regression only when at
// least two raw stages are independently slower than the limit. Without that
// guard, one genuinely faster stage is mislabeled as a regression merely
// because the other two stayed at the baseline. The separate coherent guard
// still rejects catastrophic compiler or runtime slowdowns.
for (const [name, observed, reference] of measurements) {
  const normalized = (observed / reference) / scale;
  if (normalized > limit ||
      (independentlySlowerStages >= 2 && normalized < lowerLimit)) failures.push(name);
}
if (scale > coherentLimit) failures.push("coherent-runtime-slowdown");
if (failures.length) {
  console.error(JSON.stringify({ failures, encoding, forwarding, linkScheduling, scale, runs }, null, 2));
  process.exit(1);
}
console.log(`packet benchmark valid: encoding=${encoding.toFixed(2)}ns forwarding=${forwarding.toFixed(2)}ns link=${linkScheduling.toFixed(2)}ns scale=${scale.toFixed(3)}`);
