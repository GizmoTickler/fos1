package kubernetes

import (
	"context"
	"errors"
	"regexp"
	"testing"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumfake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type stubCiliumPolicyClient struct {
	err   error
	calls int
}

func (s *stubCiliumPolicyClient) ApplyNetworkPolicy(_ context.Context, _ string, _ *ciliumv2.CiliumNetworkPolicy) error {
	s.calls++
	return s.err
}

func TestPolicyControllerProcessNextItemAppliesHighSeverityEvent(t *testing.T) {
	t.Setenv("KUBERNETES_NAMESPACE", "security")

	client := &Client{
		ciliumPolicyClient: &kubeCiliumPolicyClient{
			clientset: ciliumfake.NewSimpleClientset(),
		},
	}
	controller := NewPolicyController(client)
	t.Cleanup(controller.queue.ShutDown)

	event := DPIEvent{
		EventType:   "alert",
		Severity:    5,
		SourceIP:    "10.0.0.8",
		DestIP:      "10.0.0.22",
		Description: "SQL injection attempt blocked",
		Signature:   "ET/MALWARE SQL Injection: Attempt Against /admin",
	}

	controller.HandleDPIEvent(event)
	controller.HandleDPIEvent(event)

	if !controller.processNextItem(context.Background()) {
		t.Fatal("expected worker to keep running")
	}
	if !controller.processNextItem(context.Background()) {
		t.Fatal("expected worker to keep running on repeated event")
	}

	policies, err := client.ciliumPolicyClient.(*kubeCiliumPolicyClient).clientset.CiliumV2().
		CiliumNetworkPolicies("security").
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies.Items) != 1 {
		t.Fatalf("expected exactly one applied policy, got %d", len(policies.Items))
	}

	applied := policies.Items[0]
	expectedName := policyNameForEvent(event)
	if applied.Name != expectedName {
		t.Fatalf("expected policy name %q, got %q", expectedName, applied.Name)
	}
	if len(applied.Name) > 63 {
		t.Fatalf("policy name should be DNS-safe length, got %d chars", len(applied.Name))
	}
	if matched, err := regexp.MatchString(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, applied.Name); err != nil {
		t.Fatalf("compile name regex: %v", err)
	} else if !matched {
		t.Fatalf("policy name %q is not DNS-safe", applied.Name)
	}
	if applied.Spec == nil {
		t.Fatal("expected applied Cilium policy spec")
	}
	if len(applied.Spec.IngressDeny) != 1 {
		t.Fatalf("expected one ingress deny rule, got %d", len(applied.Spec.IngressDeny))
	}
	if len(applied.Spec.IngressDeny[0].FromCIDR) != 1 {
		t.Fatalf("expected one source CIDR, got %d", len(applied.Spec.IngressDeny[0].FromCIDR))
	}
	if got := string(applied.Spec.IngressDeny[0].FromCIDR[0]); got != "10.0.0.8/32" {
		t.Fatalf("expected source CIDR 10.0.0.8/32, got %q", got)
	}
}

func TestPolicyControllerProcessNextItemRetriesApplyFailures(t *testing.T) {
	stub := &stubCiliumPolicyClient{err: errors.New("transient apply failure")}
	controller := NewPolicyController(&Client{ciliumPolicyClient: stub})
	t.Cleanup(controller.queue.ShutDown)

	event := &DPIEvent{
		EventType: "alert",
		Severity:  4,
		SourceIP:  "10.0.0.9",
		Signature: "retry me",
	}
	controller.queue.Add(event)

	if !controller.processNextItem(context.Background()) {
		t.Fatal("expected worker to keep running")
	}
	if stub.calls != 1 {
		t.Fatalf("expected one apply attempt, got %d", stub.calls)
	}
	if got := controller.queue.NumRequeues(event); got != 1 {
		t.Fatalf("expected one requeue after failure, got %d", got)
	}
}
