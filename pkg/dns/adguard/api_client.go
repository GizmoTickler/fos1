package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APIClient provides an HTTP client for the AdGuard Home REST API.
type APIClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewAPIClient creates a new AdGuard Home API client.
func NewAPIClient(baseURL, username, password string) *APIClient {
	return &APIClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetStatus returns the current server status.
// Calls GET /control/status.
func (c *APIClient) GetStatus(ctx context.Context) (*ServerStatus, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/control/status", nil)
	if err != nil {
		return nil, fmt.Errorf("get status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var status ServerStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode status response: %w", err)
	}
	return &status, nil
}

// AddFilterList adds a new filtering list.
// Calls POST /control/filtering/add_url.
func (c *APIClient) AddFilterList(ctx context.Context, name, url string) error {
	body := addURLRequest{
		Name:    name,
		URL:     url,
		Enabled: true,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/control/filtering/add_url", body)
	if err != nil {
		return fmt.Errorf("add filter list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// RemoveFilterList removes a filtering list by URL.
// Calls POST /control/filtering/remove_url.
func (c *APIClient) RemoveFilterList(ctx context.Context, url string) error {
	body := removeURLRequest{
		URL: url,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/control/filtering/remove_url", body)
	if err != nil {
		return fmt.Errorf("remove filter list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// RefreshFilters triggers a refresh of all filter lists.
// Calls POST /control/filtering/refresh.
func (c *APIClient) RefreshFilters(ctx context.Context) error {
	body := refreshRequest{
		Whitelist: false,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/control/filtering/refresh", body)
	if err != nil {
		return fmt.Errorf("refresh filters: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// GetClients returns all configured clients.
// Calls GET /control/clients.
func (c *APIClient) GetClients(ctx context.Context) ([]ClientInfo, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/control/clients", nil)
	if err != nil {
		return nil, fmt.Errorf("get clients: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var cr clientsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decode clients response: %w", err)
	}
	return cr.Clients, nil
}

// UpdateClient updates an existing client configuration.
// Calls POST /control/clients/update.
func (c *APIClient) UpdateClient(ctx context.Context, client ClientInfo) error {
	body := updateClientRequest{
		Name: client.Name,
		Data: client,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/control/clients/update", body)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// GetStats returns DNS query statistics.
// Calls GET /control/stats.
func (c *APIClient) GetStats(ctx context.Context) (*Stats, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/control/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var stats Stats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("decode stats response: %w", err)
	}
	return &stats, nil
}

// doRequest builds and executes an HTTP request against the AdGuard Home API.
func (c *APIClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	return resp, nil
}

// readError reads the response body and returns an error with the status code and body content.
func (c *APIClient) readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
}
