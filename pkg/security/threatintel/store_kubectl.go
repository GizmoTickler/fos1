package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

// KubectlFeedStore implements FeedStore via kubectl. It is the production
// default used by the threatintel-controller binary. The unit test suite
// uses the in-memory InMemoryFeedStore instead.
//
// This implementation deliberately shells out to kubectl so the controller
// works against any kubeconfig-accessible cluster without pulling in the
// large typed-client dependency graph; this matches the pattern already
// used elsewhere in pkg/cilium for policy writes.
type KubectlFeedStore struct {
	// Kubeconfig, if non-empty, is passed to kubectl via --kubeconfig.
	Kubeconfig string

	// CLI is the kubectl command name/path. Default: "kubectl".
	CLI string
}

// NewKubectlFeedStore constructs a KubectlFeedStore with sane defaults.
func NewKubectlFeedStore() (*KubectlFeedStore, error) {
	return &KubectlFeedStore{CLI: "kubectl"}, nil
}

// List returns every ThreatFeed in the cluster (all namespaces).
func (s *KubectlFeedStore) List(ctx context.Context) ([]securityv1alpha1.ThreatFeed, error) {
	args := s.baseArgs("get", "threatfeeds.security.fos1.io", "-A", "-o", "json")
	cmd := exec.CommandContext(ctx, s.cli(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl list threatfeeds: %w\n%s", err, string(out))
	}

	var list struct {
		Items []securityv1alpha1.ThreatFeed `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("decode kubectl output: %w", err)
	}
	return list.Items, nil
}

// UpdateStatus patches the status subresource for the named feed.
func (s *KubectlFeedStore) UpdateStatus(ctx context.Context, name string, status securityv1alpha1.ThreatFeedStatus) error {
	payload, err := json.Marshal(map[string]interface{}{"status": status})
	if err != nil {
		return fmt.Errorf("encode status patch: %w", err)
	}

	args := s.baseArgs("patch", "threatfeeds.security.fos1.io", name,
		"--subresource", "status",
		"--type", "merge",
		"--patch", string(payload))

	cmd := exec.CommandContext(ctx, s.cli(), args...)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl patch status for %s: %w\n%s", name, err, string(out))
	}
	return nil
}

func (s *KubectlFeedStore) cli() string {
	if s.CLI == "" {
		return "kubectl"
	}
	return s.CLI
}

func (s *KubectlFeedStore) baseArgs(extra ...string) []string {
	args := []string{}
	if s.Kubeconfig != "" {
		args = append(args, "--kubeconfig", s.Kubeconfig)
	}
	return append(args, extra...)
}
