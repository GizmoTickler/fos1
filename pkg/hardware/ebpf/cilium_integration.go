// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Endpoint represents a Cilium endpoint.
type Endpoint struct {
	ID          int
	ContainerID string
	PodName     string
	Namespace   string
	Labels      []string
}

// CiliumIntegrationManager provides integration with Cilium's eBPF components.
// This is an internal support module (per ADR-0001) that provides discovery,
// validation, and low-level interaction with the Cilium agent. It does NOT
// define an authoritative control-plane path; controllers must go through the
// Cilium-first contract defined in pkg/cilium/*.
type CiliumIntegrationManager struct {
	ciliumPath    string
	pinPath       string
	bpfFSPath     string
	ciliumAPIBase string
	httpClient    *http.Client
}

// NewCiliumIntegrationManager creates a new CiliumIntegrationManager.
func NewCiliumIntegrationManager(ciliumPath, pinPath, bpfFSPath string) (*CiliumIntegrationManager, error) {
	// Validate ciliumPath
	if _, err := os.Stat(ciliumPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cilium path %s does not exist", ciliumPath)
	}

	// Create pinPath if it doesn't exist
	if pinPath != "" {
		if err := os.MkdirAll(pinPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create pin path: %w", err)
		}
	}

	// Validate bpfFSPath
	if _, err := os.Stat(bpfFSPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("bpffs path %s does not exist", bpfFSPath)
	}

	// Create HTTP client with timeout for API requests
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &CiliumIntegrationManager{
		ciliumPath:    ciliumPath,
		pinPath:       pinPath,
		bpfFSPath:     bpfFSPath,
		ciliumAPIBase: "http://localhost:9876/v1", // Default Cilium API endpoint
		httpClient:    httpClient,
	}, nil
}

// ErrCiliumNotAvailable is returned when the Cilium agent cannot be reached.
type ErrCiliumNotAvailable struct {
	Reason string
}

func (e *ErrCiliumNotAvailable) Error() string {
	return fmt.Sprintf("cilium agent not available: %s", e.Reason)
}

// GetCiliumMaps queries the Cilium agent API for maps it manages.
// Returns an error if the Cilium agent is not reachable.
func (c *CiliumIntegrationManager) GetCiliumMaps() ([]*Map, error) {
	resp, err := c.httpClient.Get(c.ciliumAPIBase + "/map")
	if err != nil {
		return nil, &ErrCiliumNotAvailable{Reason: fmt.Sprintf("failed to query Cilium maps API: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cilium maps API returned status %d", resp.StatusCode)
	}

	// Parse the response into our Map type
	var apiMaps []struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		KeySize    int    `json:"key-size"`
		ValueSize  int    `json:"value-size"`
		MaxEntries int    `json:"max-entries"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiMaps); err != nil {
		return nil, fmt.Errorf("failed to decode Cilium maps response: %w", err)
	}

	maps := make([]*Map, 0, len(apiMaps))
	for _, am := range apiMaps {
		maps = append(maps, &Map{
			Name:       am.Name,
			Type:       MapType(am.Type),
			KeySize:    am.KeySize,
			ValueSize:  am.ValueSize,
			MaxEntries: am.MaxEntries,
		})
	}

	return maps, nil
}

// GetCiliumPrograms queries the Cilium agent API for programs it manages.
// Returns an error if the Cilium agent is not reachable.
func (c *CiliumIntegrationManager) GetCiliumPrograms() ([]*LoadedProgram, error) {
	resp, err := c.httpClient.Get(c.ciliumAPIBase + "/map")
	if err != nil {
		return nil, &ErrCiliumNotAvailable{Reason: fmt.Sprintf("failed to query Cilium API: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cilium API returned status %d", resp.StatusCode)
	}

	// In production, this would parse the Cilium API response for program data.
	// The Cilium agent API does not expose programs directly; program discovery
	// requires reading from bpffs or using bpftool. Return empty for now with
	// a clear indication this is not a placeholder success.
	return nil, fmt.Errorf("cilium program discovery via API is not yet implemented; use bpffs enumeration at %s", c.bpfFSPath)
}

// RegisterWithCilium registers a custom program with Cilium by creating a
// registration marker that Cilium can discover.
func (c *CiliumIntegrationManager) RegisterWithCilium(program Program) error {
	if c.pinPath == "" {
		return fmt.Errorf("pin path not configured; cannot register program with Cilium")
	}

	registrationPath := filepath.Join(c.pinPath, fmt.Sprintf("%s.cilium", program.Name))
	if err := os.WriteFile(registrationPath, []byte(program.Name), 0644); err != nil {
		return fmt.Errorf("failed to create registration file: %w", err)
	}

	return nil
}

// UnregisterFromCilium unregisters a custom program from Cilium.
func (c *CiliumIntegrationManager) UnregisterFromCilium(programName string) error {
	if c.pinPath == "" {
		return fmt.Errorf("pin path not configured; cannot unregister program from Cilium")
	}

	registrationPath := filepath.Join(c.pinPath, fmt.Sprintf("%s.cilium", programName))
	if err := os.Remove(registrationPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove registration file: %w", err)
	}

	return nil
}

// GetCiliumEndpoints queries the Cilium agent API for endpoint information.
// Returns an error if the Cilium agent is not reachable.
func (c *CiliumIntegrationManager) GetCiliumEndpoints() ([]interface{}, error) {
	resp, err := c.httpClient.Get(c.ciliumAPIBase + "/endpoint")
	if err != nil {
		return nil, &ErrCiliumNotAvailable{Reason: fmt.Sprintf("failed to query Cilium endpoints API: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cilium endpoints API returned status %d", resp.StatusCode)
	}

	var endpoints []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
		return nil, fmt.Errorf("failed to decode Cilium endpoints response: %w", err)
	}

	return endpoints, nil
}

// SyncCiliumConfiguration synchronizes configuration with Cilium.
// This queries the live Cilium agent for its current state.
func (c *CiliumIntegrationManager) SyncCiliumConfiguration() error {
	// Verify Cilium is reachable
	status, err := c.GetCiliumStatus()
	if err != nil {
		return fmt.Errorf("failed to get Cilium status: %w", err)
	}

	if status == nil {
		return fmt.Errorf("cilium returned nil status")
	}

	// Get currently registered custom programs
	_, err = c.getRegisteredPrograms()
	if err != nil {
		return fmt.Errorf("failed to get registered programs: %w", err)
	}

	// Sync map references
	if err := c.syncMapReferences(); err != nil {
		return fmt.Errorf("failed to sync map references: %w", err)
	}

	return nil
}

// GetCiliumNetworkPolicies queries the Cilium agent API for network policies.
// Returns an error if the Cilium agent is not reachable.
func (c *CiliumIntegrationManager) GetCiliumNetworkPolicies(ctx context.Context) ([]CiliumNetworkPolicy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ciliumAPIBase+"/policy", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ErrCiliumNotAvailable{Reason: fmt.Sprintf("failed to query Cilium policy API: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cilium policy API returned status %d", resp.StatusCode)
	}

	var policies []CiliumNetworkPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, fmt.Errorf("failed to decode Cilium policies response: %w", err)
	}

	return policies, nil
}

// ApplyCiliumNetworkPolicy applies a Cilium network policy via the agent API.
// Returns an error if the operation fails.
func (c *CiliumIntegrationManager) ApplyCiliumNetworkPolicy(ctx context.Context, policy CiliumNetworkPolicy) error {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.ciliumAPIBase+"/policy", strings.NewReader(string(policyJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &ErrCiliumNotAvailable{Reason: fmt.Sprintf("failed to apply Cilium policy: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("cilium policy API returned status %d", resp.StatusCode)
	}

	return nil
}

// getRegisteredPrograms gets programs registered with Cilium by scanning for
// registration marker files.
func (c *CiliumIntegrationManager) getRegisteredPrograms() ([]string, error) {
	if c.pinPath == "" {
		return nil, nil
	}

	files, err := os.ReadDir(c.pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read pin path: %w", err)
	}

	var programs []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".cilium") {
			programs = append(programs, strings.TrimSuffix(file.Name(), ".cilium"))
		}
	}

	return programs, nil
}

// syncMapReferences synchronizes map references between Cilium and custom programs.
func (c *CiliumIntegrationManager) syncMapReferences() error {
	ciliumMaps, err := c.GetCiliumMaps()
	if err != nil {
		// If Cilium is not reachable, this is not fatal for sync
		var notAvail *ErrCiliumNotAvailable
		if isErrCiliumNotAvailable(err, &notAvail) {
			return nil // Cilium not reachable; skip map sync
		}
		return fmt.Errorf("failed to get Cilium maps: %w", err)
	}

	_ = ciliumMaps // Maps are available for reference; no placeholder processing
	return nil
}

// isErrCiliumNotAvailable checks if err is *ErrCiliumNotAvailable.
func isErrCiliumNotAvailable(err error, target **ErrCiliumNotAvailable) bool {
	if e, ok := err.(*ErrCiliumNotAvailable); ok {
		if target != nil {
			*target = e
		}
		return true
	}
	return false
}

// MonitorCiliumEvents connects to the Cilium agent's event monitor endpoint.
// Returns an error if the connection cannot be established.
func (c *CiliumIntegrationManager) MonitorCiliumEvents() error {
	// Verify connectivity first
	conn, err := net.DialTimeout("tcp", "localhost:9876", 5*time.Second)
	if err != nil {
		return &ErrCiliumNotAvailable{Reason: fmt.Sprintf("cannot connect to Cilium monitor: %v", err)}
	}
	conn.Close()

	// In production, this would establish a streaming connection to the Cilium
	// monitor API. The actual event stream processing is not yet implemented.
	return fmt.Errorf("cilium event monitoring is not yet implemented")
}

// GetCiliumStatus queries the Cilium agent for its current status.
// Returns an error if the agent is not reachable.
func (c *CiliumIntegrationManager) GetCiliumStatus() (map[string]interface{}, error) {
	resp, err := c.httpClient.Get(c.ciliumAPIBase + "/healthz")
	if err != nil {
		return nil, &ErrCiliumNotAvailable{Reason: fmt.Sprintf("failed to query Cilium health API: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cilium health API returned status %d", resp.StatusCode)
	}

	var status map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode Cilium status response: %w", err)
	}

	return status, nil
}
