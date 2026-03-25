package adguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer creates an httptest.NewServer that handles the AdGuard Home
// API endpoints used by APIClient.
func newTestServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/control/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp := ServerStatus{
			DNSAddresses:      []string{"0.0.0.0"},
			DNSPort:           53,
			HTTPPort:          3000,
			ProtectionEnabled: true,
			Running:           true,
			Version:           "v0.107.0",
			Language:          "en",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/control/filtering/add_url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req addURLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Name == "" || req.URL == "" {
			http.Error(w, "name and url are required", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/control/filtering/remove_url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req removeURLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.URL == "" {
			http.Error(w, "url is required", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/control/filtering/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/control/clients", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp := clientsResponse{
			Clients: []ClientInfo{
				{
					Name:              "TestClient",
					IDs:               []string{"192.168.1.100"},
					Tags:              []string{"user_regular"},
					UseGlobalSettings: true,
					FilteringEnabled:  true,
				},
				{
					Name:              "IoTDevice",
					IDs:               []string{"192.168.1.200"},
					Tags:              []string{"device_other"},
					UseGlobalSettings: false,
					FilteringEnabled:  true,
					BlockedServices:   []string{"facebook", "tiktok"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/control/clients/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req updateClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/control/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp := Stats{
			NumDNSQueries:       12345,
			NumBlockedFiltering: 1234,
			AvgProcessingTime:   0.005,
			TopQueriedDomains: []map[string]int64{
				{"example.com": 500},
			},
			TopBlockedDomains: []map[string]int64{
				{"ads.example.com": 100},
			},
			TopClients: []map[string]int64{
				{"192.168.1.100": 3000},
			},
			DNSQueries:       []int64{100, 200, 300},
			BlockedFiltering: []int64{10, 20, 30},
			TimeUnits:        "hours",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

func TestGetStatus(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	status, err := client.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}

	if !status.Running {
		t.Error("expected Running to be true")
	}
	if status.Version != "v0.107.0" {
		t.Errorf("expected version v0.107.0, got %s", status.Version)
	}
	if !status.ProtectionEnabled {
		t.Error("expected ProtectionEnabled to be true")
	}
	if status.DNSPort != 53 {
		t.Errorf("expected DNSPort 53, got %d", status.DNSPort)
	}
}

func TestAddFilterList(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	err := client.AddFilterList(context.Background(), "TestList", "https://example.com/blocklist.txt")
	if err != nil {
		t.Fatalf("AddFilterList returned error: %v", err)
	}
}

func TestAddFilterList_EmptyFields(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	err := client.AddFilterList(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected error for empty name and url, got nil")
	}
}

func TestRemoveFilterList(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	err := client.RemoveFilterList(context.Background(), "https://example.com/blocklist.txt")
	if err != nil {
		t.Fatalf("RemoveFilterList returned error: %v", err)
	}
}

func TestRemoveFilterList_EmptyURL(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	err := client.RemoveFilterList(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty url, got nil")
	}
}

func TestRefreshFilters(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	err := client.RefreshFilters(context.Background())
	if err != nil {
		t.Fatalf("RefreshFilters returned error: %v", err)
	}
}

func TestGetClients(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	clients, err := client.GetClients(context.Background())
	if err != nil {
		t.Fatalf("GetClients returned error: %v", err)
	}

	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
	if clients[0].Name != "TestClient" {
		t.Errorf("expected first client name TestClient, got %s", clients[0].Name)
	}
	if clients[1].Name != "IoTDevice" {
		t.Errorf("expected second client name IoTDevice, got %s", clients[1].Name)
	}
	if len(clients[1].BlockedServices) != 2 {
		t.Errorf("expected 2 blocked services for IoTDevice, got %d", len(clients[1].BlockedServices))
	}
}

func TestUpdateClient(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	err := client.UpdateClient(context.Background(), ClientInfo{
		Name:             "TestClient",
		IDs:              []string{"192.168.1.100"},
		FilteringEnabled: true,
		BlockedServices:  []string{"facebook"},
	})
	if err != nil {
		t.Fatalf("UpdateClient returned error: %v", err)
	}
}

func TestGetStats(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "admin", "password")
	stats, err := client.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats returned error: %v", err)
	}

	if stats.NumDNSQueries != 12345 {
		t.Errorf("expected 12345 DNS queries, got %d", stats.NumDNSQueries)
	}
	if stats.NumBlockedFiltering != 1234 {
		t.Errorf("expected 1234 blocked queries, got %d", stats.NumBlockedFiltering)
	}
	if stats.AvgProcessingTime != 0.005 {
		t.Errorf("expected avg processing time 0.005, got %f", stats.AvgProcessingTime)
	}
	if stats.TimeUnits != "hours" {
		t.Errorf("expected time units hours, got %s", stats.TimeUnits)
	}
}

func TestBasicAuth(t *testing.T) {
	var receivedUser, receivedPass string
	var authOK bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser, receivedPass, authOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ServerStatus{Running: true})
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL, "myuser", "mypass")
	_, err := client.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}

	if !authOK {
		t.Fatal("expected basic auth to be present")
	}
	if receivedUser != "myuser" {
		t.Errorf("expected username myuser, got %s", receivedUser)
	}
	if receivedPass != "mypass" {
		t.Errorf("expected password mypass, got %s", receivedPass)
	}
}

func TestServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL, "", "")
	_, err := client.GetStatus(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestContextCancellation(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := NewAPIClient(srv.URL, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.GetStatus(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
