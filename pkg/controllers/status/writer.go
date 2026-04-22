// Package status provides shared helpers for writing CRD status subresource
// updates with retry-on-conflict semantics.
//
// Every FOS1 controller that owns a CRD needs to persist reconciled status
// back to the API server: Applied/Degraded/Invalid conditions, observed
// generation, last-applied hashes, and so on. Prior to this package that
// logic lived inline in each controller (NAT, BGP, OSPF, routing policy,
// QoS, multi-WAN) as a `writeStatusToCRD` method that duplicated the same
// shape: deep-copy the object, set nested fields, call UpdateStatus. The
// inline variant also skipped retry-on-conflict, which made the controllers
// prone to losing status updates under leader changes or racing reconcile
// loops.
//
// Writer centralises that pattern. Callers hand it a dynamic client, a
// target GroupVersionResource, and a per-object mutator; the helper applies
// the mutator and invokes UpdateStatus inside a retry.RetryOnConflict loop
// that re-fetches the latest object on conflict before re-applying the
// mutator.
package status

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
)

// Writer persists CRD status subresource mutations with retry-on-conflict.
//
// A Writer is immutable after construction and safe to share across goroutines
// as long as the underlying dynamic.Interface is thread-safe (the real
// client-go implementation is).
type Writer struct {
	// Client is the dynamic Kubernetes client used to read and write the
	// CRD status subresource. Required.
	Client dynamic.Interface

	// GVR identifies the target CRD. Required.
	GVR schema.GroupVersionResource
}

// NewWriter returns a Writer wired to the given dynamic client and GVR.
func NewWriter(client dynamic.Interface, gvr schema.GroupVersionResource) *Writer {
	return &Writer{Client: client, GVR: gvr}
}

// Mutator is invoked on each WriteStatus attempt with the object whose
// status.* fields the caller wants to update. On a successful first attempt
// the mutator sees the exact *unstructured.Unstructured passed to
// WriteStatus; on a conflict-driven retry the mutator sees the latest copy
// re-fetched from the API server.
//
// A Mutator must be idempotent: it may be called more than once for the
// same logical write and must produce the same status fields each time
// (given the same spec). Returning an error aborts the write and the error
// is propagated out of WriteStatus wrapped with GVR and namespace/name
// context.
type Mutator func(obj *unstructured.Unstructured) error

// WriteStatus applies the given mutator to obj and writes the CRD status
// subresource with retry-on-conflict.
//
// Behaviour:
//
//  1. First attempt uses the passed-in obj directly. This preserves the
//     existing controller contract where the caller has already materialised
//     the object (e.g. from an informer cache) and wants to apply status
//     without a redundant API round-trip.
//  2. On a conflict error from UpdateStatus, the helper re-fetches the
//     latest copy via Client.Resource(GVR).Namespace(ns).Get(...) and re-runs
//     the mutator against the fresh object. This is the contract documented
//     by client-go's retry.RetryOnConflict.
//  3. Retries use retry.DefaultBackoff (4 attempts, ~10ms starting delay,
//     factor 5.0, ~10% jitter). If every attempt conflicts the helper
//     returns the last conflict error wrapped with GVR + namespace/name.
//  4. Non-conflict errors (NotFound, Forbidden, network, mutator error)
//     short-circuit immediately; they are wrapped with the same context and
//     returned to the caller.
//
// On first-attempt success, the mutator is called exactly once and only one
// UpdateStatus call is issued against the API server.
func (w *Writer) WriteStatus(
	ctx context.Context,
	obj *unstructured.Unstructured,
	mutate Mutator,
) error {
	if w == nil || w.Client == nil {
		return fmt.Errorf("status.Writer: nil client")
	}
	if mutate == nil {
		return fmt.Errorf("status.Writer: nil mutator")
	}
	if obj == nil {
		return fmt.Errorf("status.Writer: nil object")
	}

	namespace := obj.GetNamespace()
	name := obj.GetName()

	// current tracks the object the next mutator invocation should see.
	// The first attempt uses the caller-supplied obj so a hot-path apply
	// does not require a redundant Get; subsequent attempts refresh it.
	current := obj
	firstAttempt := true

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		if !firstAttempt {
			latest, getErr := w.Client.
				Resource(w.GVR).
				Namespace(namespace).
				Get(ctx, name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			current = latest
		}
		firstAttempt = false

		if err := mutate(current); err != nil {
			// Mutator errors are not retriable via RetryOnConflict
			// (errors.IsConflict returns false) so this short-circuits.
			return fmt.Errorf("status mutator: %w", err)
		}

		_, updateErr := w.Client.
			Resource(w.GVR).
			Namespace(namespace).
			UpdateStatus(ctx, current, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return fmt.Errorf(
			"write status for %s %s/%s: %w",
			w.GVR.String(), namespace, name, err,
		)
	}
	return nil
}
