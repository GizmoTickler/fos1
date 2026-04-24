// Package bench hosts performance benchmarks for FOS1 hot paths.
//
// This package contains only benchmark tests (_test.go files). It is
// not imported by production code.
//
// Hot paths covered:
//
//   - pkg/network/nat.manager.ApplyNATPolicy — sprint 30 / ticket 43
//     (nat_apply_bench_test.go)
//   - pkg/security/dpi.PolicyPipeline.ProcessEvent — sprint 31 /
//     ticket 54 (dpi_policy_bench_test.go)
//   - pkg/security/policy.CiliumPolicyTranslator.TranslatePolicy —
//     sprint 31 / ticket 54 (filterpolicy_translate_bench_test.go)
//   - pkg/security/threatintel.Translator.Translate — sprint 31 /
//     ticket 54 (threatintel_translate_bench_test.go)
//
// All benchmarks follow the same shape: isolate the hot path behind
// a minimal in-process fake (where one is needed), silence klog in
// TestMain, and emit scales at 1 / 100 / 1000 inputs so the CI
// regression script can track the per-scale median ns/op.
//
// See docs/performance/README.md for how to run the benches and
// interpret the numbers, and docs/performance/baseline-2026-04.md for
// the active baseline values the regression check compares against.
package bench
