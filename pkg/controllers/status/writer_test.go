package status

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/util/retry"
	clienttesting "k8s.io/client-go/testing"
)

var testGVR = schema.GroupVersionResource{
	Group:    "example.fos1.io",
	Version:  "v1alpha1",
	Resource: "widgets",
}

// makeWidget returns a minimal unstructured CRD object shaped like a
// typical FOS1 status-bearing resource. The caller may mutate the returned
// object freely — each call produces a fresh map.
func makeWidget(name, namespace string, generation int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "example.fos1.io/v1alpha1",
			"kind":       "Widget",
			"metadata": map[string]interface{}{
				"name":            name,
				"namespace":       namespace,
				"generation":      generation,
				"resourceVersion": "1",
			},
			"spec": map[string]interface{}{
				"replicas": int64(3),
			},
		},
	}
}

// newFakeClient returns a fake dynamic client pre-populated with the
// provided CRD objects. Callers that want updates to succeed without
// seeding the object may use newFakeClientWithOpenUpdates instead.
func newFakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClient(scheme, objects...)
}

// newFakeClientWithOpenUpdates mirrors the shape of the NAT controller
// tests (pkg/controllers/nat_controller_test.go:204): no seeded objects,
// but a permissive update reactor that accepts the status subresource
// write without requiring the object to exist. Used to exercise the
// first-attempt happy path without forcing the Writer's re-fetch code
// to be reachable by tests that do not exercise conflict.
func newFakeClientWithOpenUpdates() *dynamicfake.FakeDynamicClient {
	client := newFakeClient()
	client.PrependReactor("update", testGVR.Resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		upd, ok := action.(clienttesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		return true, upd.GetObject(), nil
	})
	return client
}

// setReady is a representative Mutator that records an Applied=True
// condition on the widget's status subresource. Shape mirrors the NAT
// controller's status writes at pkg/controllers/nat_controller.go.
func setReady(now time.Time) Mutator {
	return func(obj *unstructured.Unstructured) error {
		conditions := []interface{}{
			map[string]interface{}{
				"type":               "Applied",
				"status":             "True",
				"reason":             "Reconciled",
				"message":            "applied",
				"lastTransitionTime": now.Format(time.RFC3339),
			},
		}
		return unstructured.SetNestedSlice(obj.Object, conditions, "status", "conditions")
	}
}

// TestWriteStatus_SuccessOnFirstTry covers the hot-path: no conflict, the
// mutator is invoked exactly once, and exactly one UpdateStatus call is
// issued against the API server.
func TestWriteStatus_SuccessOnFirstTry(t *testing.T) {
	fake := newFakeClientWithOpenUpdates()
	writer := NewWriter(fake, testGVR)

	obj := makeWidget("widget-1", "default", 1)
	now := time.Unix(1_700_000_000, 0).UTC()

	var mutatorCalls int
	mut := func(o *unstructured.Unstructured) error {
		mutatorCalls++
		return setReady(now)(o)
	}

	if err := writer.WriteStatus(context.Background(), obj, mut); err != nil {
		t.Fatalf("unexpected WriteStatus error: %v", err)
	}

	if mutatorCalls != 1 {
		t.Fatalf("expected mutator invoked exactly once, got %d calls", mutatorCalls)
	}

	actions := fake.Actions()
	if len(actions) != 1 {
		t.Fatalf("expected exactly 1 fake action, got %d: %+v", len(actions), actions)
	}
	got := actions[0]
	if got.GetVerb() != "update" || got.GetSubresource() != "status" {
		t.Fatalf("expected update on status subresource, got %s/%s",
			got.GetVerb(), got.GetSubresource())
	}
	if got.GetResource() != testGVR {
		t.Fatalf("expected GVR %v, got %v", testGVR, got.GetResource())
	}

	// Confirm the mutator actually applied the expected status condition
	// on the object that was passed to UpdateStatus.
	updated := got.(clienttesting.UpdateActionImpl).GetObject().(*unstructured.Unstructured)
	conds, found, err := unstructured.NestedSlice(updated.Object, "status", "conditions")
	if err != nil || !found {
		t.Fatalf("expected status.conditions to be set, found=%v err=%v", found, err)
	}
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}
	cond := conds[0].(map[string]interface{})
	if cond["type"] != "Applied" || cond["status"] != "True" {
		t.Fatalf("unexpected condition: %+v", cond)
	}
}

// TestWriteStatus_RetriesOnConflict drives the conflict path: the first
// UpdateStatus returns a Conflict, the helper re-fetches the latest copy
// (via Get) and the second UpdateStatus succeeds. Asserts (a) the mutator
// is re-invoked against the re-fetched object, and (b) the re-fetched copy
// — not the original obj — is passed to the final UpdateStatus.
func TestWriteStatus_RetriesOnConflict(t *testing.T) {
	obj := makeWidget("widget-2", "team-b", 2)

	// Seed the fake with the widget so that the conflict-triggered Get
	// returns a valid object. We mark it with a distinct resourceVersion
	// so the test can prove the mutator saw the freshly-fetched copy.
	latestCopy := obj.DeepCopy()
	latestCopy.SetResourceVersion("42")

	fake := newFakeClient(latestCopy)

	// Force exactly one Conflict on the first UpdateStatus; subsequent
	// UpdateStatus calls succeed. Track whether the reactor has fired yet
	// using an int32 so the test is race-free under -race.
	var conflictsFired int32
	fake.PrependReactor("update", testGVR.Resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		upd, ok := action.(clienttesting.UpdateAction)
		if !ok || upd.GetSubresource() != "status" {
			return false, nil, nil
		}
		if atomic.AddInt32(&conflictsFired, 1) == 1 {
			return true, nil, apierrors.NewConflict(
				testGVR.GroupResource(),
				obj.GetName(),
				errors.New("simulated conflict"),
			)
		}
		// Fall through to the default reactor (which will accept the
		// update and record it in the tracker).
		return false, nil, nil
	})

	writer := NewWriter(fake, testGVR)

	var (
		mutatorCalls        int
		lastSeenRVByMutator string
	)
	mut := func(o *unstructured.Unstructured) error {
		mutatorCalls++
		lastSeenRVByMutator = o.GetResourceVersion()
		return setReady(time.Unix(0, 0))(o)
	}

	if err := writer.WriteStatus(context.Background(), obj, mut); err != nil {
		t.Fatalf("unexpected WriteStatus error: %v", err)
	}

	if mutatorCalls != 2 {
		t.Fatalf("expected mutator called twice (once before conflict, once after re-fetch), got %d",
			mutatorCalls)
	}
	if lastSeenRVByMutator != "42" {
		t.Fatalf("expected second mutator call to see re-fetched resourceVersion=42, got %q",
			lastSeenRVByMutator)
	}

	// Expect 3 actions: UpdateStatus (conflict) -> Get -> UpdateStatus (ok).
	actions := fake.Actions()
	if len(actions) != 3 {
		t.Fatalf("expected 3 fake actions (update/get/update), got %d: %+v",
			len(actions), actionVerbs(actions))
	}
	if actions[0].GetVerb() != "update" || actions[0].GetSubresource() != "status" {
		t.Fatalf("action[0] expected update/status, got %s/%s",
			actions[0].GetVerb(), actions[0].GetSubresource())
	}
	if actions[1].GetVerb() != "get" {
		t.Fatalf("action[1] expected get, got %s", actions[1].GetVerb())
	}
	if actions[2].GetVerb() != "update" || actions[2].GetSubresource() != "status" {
		t.Fatalf("action[2] expected update/status, got %s/%s",
			actions[2].GetVerb(), actions[2].GetSubresource())
	}
}

// TestWriteStatus_GivesUpAfterBackoff asserts the helper surfaces the
// final conflict error (with GVR + namespace/name context) when every
// retry attempt conflicts. Uses a shortened backoff to keep the test fast.
func TestWriteStatus_GivesUpAfterBackoff(t *testing.T) {
	obj := makeWidget("widget-3", "team-c", 3)
	fake := newFakeClient(obj.DeepCopy())

	// Every UpdateStatus returns Conflict — exhausts the retry budget.
	fake.PrependReactor("update", testGVR.Resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		upd, ok := action.(clienttesting.UpdateAction)
		if !ok || upd.GetSubresource() != "status" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewConflict(
			testGVR.GroupResource(),
			obj.GetName(),
			errors.New("persistent conflict"),
		)
	})

	writer := NewWriter(fake, testGVR)

	// The helper uses retry.DefaultBackoff which is fast enough
	// (~10ms * 5^steps) that we do not need to plumb a shortened backoff
	// into Writer. If the default balloons in a future client-go bump
	// (>1s per attempt) we should revisit.
	start := time.Now()
	err := writer.WriteStatus(context.Background(), obj, setReady(time.Unix(0, 0)))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected WriteStatus to return an error after exhausted retries")
	}
	if !apierrors.IsConflict(errors.Unwrap(err)) && !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflict-wrapped error, got: %v", err)
	}
	wantGVR := testGVR.String()
	if !strings.Contains(err.Error(), wantGVR) {
		t.Fatalf("expected wrapped error to mention GVR %q, got: %v", wantGVR, err)
	}
	if !strings.Contains(err.Error(), "team-c/widget-3") {
		t.Fatalf("expected wrapped error to mention namespace/name, got: %v", err)
	}

	// Sanity bound: the retry loop should not take > 2s even with default
	// backoff; if it does, something is wrong with the retry plumbing.
	if elapsed > 2*time.Second {
		t.Fatalf("retry loop took too long (%v); expected < 2s", elapsed)
	}

	// Expect N UpdateStatus attempts and (N-1) Gets (first attempt skips Get).
	updates, gets := countVerbs(fake.Actions(), "update", "get")
	if updates < retry.DefaultBackoff.Steps {
		t.Fatalf("expected at least %d update attempts, got %d",
			retry.DefaultBackoff.Steps, updates)
	}
	if gets != updates-1 {
		t.Fatalf("expected gets=updates-1 (re-fetch only after conflict); updates=%d gets=%d",
			updates, gets)
	}
}

// TestWriteStatus_NilGuards documents the defensive checks — ensures the
// helper refuses to proceed on obviously broken inputs rather than
// panicking mid-reconcile.
func TestWriteStatus_NilGuards(t *testing.T) {
	obj := makeWidget("w", "ns", 1)
	fake := newFakeClientWithOpenUpdates()

	cases := []struct {
		name   string
		writer *Writer
		obj    *unstructured.Unstructured
		mut    Mutator
	}{
		{"nil writer", nil, obj, setReady(time.Unix(0, 0))},
		{"nil client", &Writer{GVR: testGVR}, obj, setReady(time.Unix(0, 0))},
		{"nil mutator", NewWriter(fake, testGVR), obj, nil},
		{"nil object", NewWriter(fake, testGVR), nil, setReady(time.Unix(0, 0))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.writer.WriteStatus(context.Background(), tc.obj, tc.mut)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

// TestWriteStatus_MutatorErrorIsNotRetried ensures a non-conflict mutator
// error short-circuits the retry loop: RetryOnConflict should not treat
// arbitrary errors as retriable.
func TestWriteStatus_MutatorErrorIsNotRetried(t *testing.T) {
	obj := makeWidget("w", "ns", 1)
	fake := newFakeClientWithOpenUpdates()
	writer := NewWriter(fake, testGVR)

	var mutatorCalls int
	mut := func(*unstructured.Unstructured) error {
		mutatorCalls++
		return errors.New("boom")
	}

	err := writer.WriteStatus(context.Background(), obj, mut)
	if err == nil {
		t.Fatal("expected error when mutator fails")
	}
	if mutatorCalls != 1 {
		t.Fatalf("expected mutator called exactly once (no retry on non-conflict errors), got %d",
			mutatorCalls)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected mutator error to propagate, got: %v", err)
	}
}

// actionVerbs returns a compact slice of "verb/subresource" strings for a
// list of fake actions. Used to produce readable assertion failures.
func actionVerbs(actions []clienttesting.Action) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		sr := a.GetSubresource()
		if sr == "" {
			out[i] = a.GetVerb()
		} else {
			out[i] = a.GetVerb() + "/" + sr
		}
	}
	return out
}

// countVerbs counts how many actions match each requested verb. Subresource
// filtering is intentionally not applied here; callers that care can filter
// via actionVerbs first.
func countVerbs(actions []clienttesting.Action, verbs ...string) (int, int) {
	if len(verbs) != 2 {
		return 0, 0
	}
	var a, b int
	for _, act := range actions {
		switch act.GetVerb() {
		case verbs[0]:
			a++
		case verbs[1]:
			b++
		}
	}
	return a, b
}

// Compile-time assertion that dynamic.Interface implements what Writer
// uses. Keeps the helper compiling cleanly if client-go's dynamic surface
// ever changes.
var _ dynamic.Interface = (*dynamicfake.FakeDynamicClient)(nil)

// Compile-time assertion so retry.DefaultBackoff stays a wait.Backoff even
// if we bump client-go majorly.
var _ wait.Backoff = retry.DefaultBackoff
