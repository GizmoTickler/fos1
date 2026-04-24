package threatintel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
)

// InMemorySecretReader implements SecretReader from a namespaced map. Used by
// tests and by the harness to inject canned credentials without any real
// cluster access. All operations are safe for concurrent use.
type InMemorySecretReader struct {
	mu    sync.Mutex
	data  map[string]map[string][]byte // key = "ns/name"
	Error error                        // if non-nil, every Read returns this
}

// NewInMemorySecretReader constructs an empty reader.
func NewInMemorySecretReader() *InMemorySecretReader {
	return &InMemorySecretReader{data: make(map[string]map[string][]byte)}
}

// Put stores the data for the given (namespace, name). Replaces any prior
// entry at the same coordinates.
func (r *InMemorySecretReader) Put(namespace, name string, data map[string][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := namespace + "/" + name
	cp := make(map[string][]byte, len(data))
	for key, val := range data {
		bb := make([]byte, len(val))
		copy(bb, val)
		cp[key] = bb
	}
	r.data[k] = cp
}

// Read implements SecretReader.
func (r *InMemorySecretReader) Read(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Error != nil {
		return nil, r.Error
	}
	data, ok := r.data[namespace+"/"+name]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s not found", namespace, name)
	}
	out := make(map[string][]byte, len(data))
	for k, v := range data {
		bb := make([]byte, len(v))
		copy(bb, v)
		out[k] = bb
	}
	return out, nil
}

// KubectlSecretReader implements SecretReader via `kubectl get secret -o json`,
// mirroring the pattern used by KubectlFeedStore. Production binaries wire
// this up; tests use InMemorySecretReader.
type KubectlSecretReader struct {
	// Kubeconfig, if non-empty, is passed via --kubeconfig.
	Kubeconfig string

	// CLI is the kubectl command name. Default: "kubectl".
	CLI string
}

// Read implements SecretReader.
func (r *KubectlSecretReader) Read(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	cli := r.CLI
	if cli == "" {
		cli = "kubectl"
	}
	args := []string{}
	if r.Kubeconfig != "" {
		args = append(args, "--kubeconfig", r.Kubeconfig)
	}
	args = append(args, "get", "secret", name, "-n", namespace, "-o", "json")

	cmd := exec.CommandContext(ctx, cli, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl get secret %s/%s: %w\n%s", namespace, name, err, string(out))
	}

	// Secret.data values are base64-encoded strings.
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}
	decoded := make(map[string][]byte, len(payload.Data))
	for k, v := range payload.Data {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("secret %s/%s: decode key %q: %w", namespace, name, k, err)
		}
		decoded[k] = b
	}
	return decoded, nil
}
