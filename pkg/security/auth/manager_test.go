package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/GizmoTickler/fos1/pkg/security/auth"
	// Import providers to trigger init() registration of constructors
	_ "github.com/GizmoTickler/fos1/pkg/security/auth/providers"
)

// TestNewLocalProvider_Success verifies that a local provider can be
// instantiated through the manager factory with valid configuration.
func TestNewLocalProvider_Success(t *testing.T) {
	info := &auth.ProviderInfo{
		Name:    "test-local",
		Type:    "local",
		Enabled: true,
		Config: auth.ProviderConfig{
			Local: &auth.LocalConfig{
				PasswordPolicy: auth.PasswordPolicy{
					MinLength: 8,
				},
			},
		},
	}

	provider, err := auth.NewLocalProvider(info)
	if err != nil {
		t.Fatalf("expected no error creating local provider, got: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	providerInfo := provider.GetInfo()
	if providerInfo.Type != "local" {
		t.Errorf("expected provider type 'local', got %q", providerInfo.Type)
	}
}

// TestNewLocalProvider_NilInfo verifies that passing nil info returns an error.
func TestNewLocalProvider_NilInfo(t *testing.T) {
	_, err := auth.NewLocalProvider(nil)
	if err == nil {
		t.Fatal("expected error for nil info, got nil")
	}
}

// TestNewLocalProvider_NilConfig verifies that missing local config returns an error.
func TestNewLocalProvider_NilConfig(t *testing.T) {
	info := &auth.ProviderInfo{
		Name: "test-local",
		Type: "local",
		Config: auth.ProviderConfig{
			// Local is nil
		},
	}

	_, err := auth.NewLocalProvider(info)
	if err == nil {
		t.Fatal("expected error for nil local config, got nil")
	}
}

// TestNewLDAPProvider_Success verifies that an LDAP provider can be
// instantiated through the manager factory with valid configuration.
func TestNewLDAPProvider_Success(t *testing.T) {
	info := &auth.ProviderInfo{
		Name:    "test-ldap",
		Type:    "ldap",
		Enabled: true,
		Config: auth.ProviderConfig{
			LDAP: &auth.LDAPConfig{
				URL:        "ldap://localhost:389",
				UserBaseDN: "dc=example,dc=com",
				UserFilter: "(uid=%s)",
			},
		},
	}

	provider, err := auth.NewLDAPProvider(info)
	if err != nil {
		t.Fatalf("expected no error creating LDAP provider, got: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	providerInfo := provider.GetInfo()
	if providerInfo.Type != "ldap" {
		t.Errorf("expected provider type 'ldap', got %q", providerInfo.Type)
	}
}

// TestNewLDAPProvider_NilInfo verifies nil info returns an error.
func TestNewLDAPProvider_NilInfo(t *testing.T) {
	_, err := auth.NewLDAPProvider(nil)
	if err == nil {
		t.Fatal("expected error for nil info, got nil")
	}
}

// TestNewLDAPProvider_MissingURL verifies that missing LDAP URL returns an error.
func TestNewLDAPProvider_MissingURL(t *testing.T) {
	info := &auth.ProviderInfo{
		Name: "test-ldap",
		Type: "ldap",
		Config: auth.ProviderConfig{
			LDAP: &auth.LDAPConfig{
				UserBaseDN: "dc=example,dc=com",
				// URL is missing
			},
		},
	}

	_, err := auth.NewLDAPProvider(info)
	if err == nil {
		t.Fatal("expected error for missing LDAP URL, got nil")
	}
}

// TestNewLDAPProvider_MissingBaseDN verifies that missing user base DN returns an error.
func TestNewLDAPProvider_MissingBaseDN(t *testing.T) {
	info := &auth.ProviderInfo{
		Name: "test-ldap",
		Type: "ldap",
		Config: auth.ProviderConfig{
			LDAP: &auth.LDAPConfig{
				URL: "ldap://localhost:389",
				// UserBaseDN is missing
			},
		},
	}

	_, err := auth.NewLDAPProvider(info)
	if err == nil {
		t.Fatal("expected error for missing user base DN, got nil")
	}
}

// TestNewOAuthProvider_Success verifies that an OAuth provider can be
// instantiated through the manager factory with valid configuration.
func TestNewOAuthProvider_Success(t *testing.T) {
	info := &auth.ProviderInfo{
		Name:    "test-oauth",
		Type:    "oauth",
		Enabled: true,
		Config: auth.ProviderConfig{
			OAuth: &auth.OAuthConfig{
				ProviderType:     "generic",
				ClientID:         "test-client-id",
				ClientSecret:     "test-client-secret",
				AuthorizationURL: "https://auth.example.com/authorize",
				TokenURL:         "https://auth.example.com/token",
				UserInfoURL:      "https://auth.example.com/userinfo",
				RedirectURL:      "https://myapp.example.com/callback",
				Scopes:           []string{"openid", "profile"},
			},
		},
	}

	provider, err := auth.NewOAuthProvider(info)
	if err != nil {
		t.Fatalf("expected no error creating OAuth provider, got: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	providerInfo := provider.GetInfo()
	if providerInfo.Type != "oauth" {
		t.Errorf("expected provider type 'oauth', got %q", providerInfo.Type)
	}
}

// TestNewOAuthProvider_NilInfo verifies nil info returns an error.
func TestNewOAuthProvider_NilInfo(t *testing.T) {
	_, err := auth.NewOAuthProvider(nil)
	if err == nil {
		t.Fatal("expected error for nil info, got nil")
	}
}

// TestNewOAuthProvider_MissingClientID verifies missing client ID returns an error.
func TestNewOAuthProvider_MissingClientID(t *testing.T) {
	info := &auth.ProviderInfo{
		Name: "test-oauth",
		Type: "oauth",
		Config: auth.ProviderConfig{
			OAuth: &auth.OAuthConfig{
				ProviderType: "generic",
				ClientSecret: "secret",
			},
		},
	}

	_, err := auth.NewOAuthProvider(info)
	if err == nil {
		t.Fatal("expected error for missing client ID, got nil")
	}
}

// TestNewOAuthProvider_MissingClientSecret verifies missing client secret returns an error.
func TestNewOAuthProvider_MissingClientSecret(t *testing.T) {
	info := &auth.ProviderInfo{
		Name: "test-oauth",
		Type: "oauth",
		Config: auth.ProviderConfig{
			OAuth: &auth.OAuthConfig{
				ProviderType: "generic",
				ClientID:     "client-id",
			},
		},
	}

	_, err := auth.NewOAuthProvider(info)
	if err == nil {
		t.Fatal("expected error for missing client secret, got nil")
	}
}

// TestAddProviderRejectsUnsupportedType verifies that the manager rejects
// removed provider types (saml, radius, certificate) along with any other
// unknown type, with an error message that names the supported types.
//
// See Sprint 29 Ticket 34 for the decision to remove SAML, RADIUS, and
// certificate provider stubs from the auth factory.
func TestAddProviderRejectsUnsupportedType(t *testing.T) {
	for _, tpe := range []string{"saml", "radius", "certificate", "notarealtype"} {
		t.Run(tpe, func(t *testing.T) {
			mgr, err := auth.NewAuthManager(nil)
			if err != nil {
				t.Fatalf("failed to create auth manager: %v", err)
			}
			err = mgr.AddProvider(&auth.ProviderInfo{Name: "t", Type: tpe})
			if err == nil {
				t.Fatalf("expected error for provider type %q, got nil", tpe)
			}
			msg := err.Error()
			if !strings.Contains(msg, "unsupported auth provider type") {
				t.Errorf("error message missing 'unsupported auth provider type': %v", err)
			}
			if !strings.Contains(msg, "local, ldap, oauth") {
				t.Errorf("error message missing 'local, ldap, oauth': %v", err)
			}
		})
	}
}

// TestAddProvider_Local verifies that AddProvider successfully creates and
// registers a local provider through the manager.
func TestAddProvider_Local(t *testing.T) {
	mgr, err := auth.NewAuthManager(nil)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	info := &auth.ProviderInfo{
		Name:    "test-local",
		Type:    "local",
		Enabled: true,
		Config: auth.ProviderConfig{
			Local: &auth.LocalConfig{
				PasswordPolicy: auth.PasswordPolicy{MinLength: 8},
			},
		},
	}

	err = mgr.AddProvider(info)
	if err != nil {
		t.Fatalf("AddProvider failed: %v", err)
	}

	// Verify it's listed
	providers, err := mgr.ListProviders()
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0].Name != "test-local" {
		t.Errorf("expected provider name 'test-local', got %q", providers[0].Name)
	}
}

// TestLocalProvider_AuthFlow verifies end-to-end authentication with the
// local provider: initialize, create user, authenticate, validate token,
// revoke token.
func TestLocalProvider_AuthFlow(t *testing.T) {
	mgr, err := auth.NewAuthManager(&auth.Config{
		DefaultProvider:        "local",
		TokenExpiration:        3600,
		RefreshTokenExpiration: 86400,
		EnableAuditLogging:     false,
	})
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	// Add a local provider
	info := &auth.ProviderInfo{
		Name:    "local",
		Type:    "local",
		Enabled: true,
		Config: auth.ProviderConfig{
			Local: &auth.LocalConfig{},
		},
	}

	err = mgr.AddProvider(info)
	if err != nil {
		t.Fatalf("AddProvider failed: %v", err)
	}

	// Initialize the manager (this creates the default admin user)
	err = mgr.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Authenticate with the default admin credentials
	resp, err := mgr.Authenticate(&auth.AuthRequest{
		Username: "admin",
		Password: "admin",
		Provider: "local",
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected authentication success, got failure: %s", resp.Error)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Validate the token
	tokenInfo, err := mgr.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if tokenInfo.Username != "admin" {
		t.Errorf("expected username 'admin', got %q", tokenInfo.Username)
	}

	// Revoke the token
	err = mgr.RevokeToken(resp.Token)
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	// Token should no longer be valid
	_, err = mgr.ValidateToken(resp.Token)
	if err == nil {
		t.Fatal("expected error validating revoked token, got nil")
	}

	// Shutdown
	err = mgr.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}

// TestLocalProvider_BadPassword verifies that incorrect passwords are rejected.
func TestLocalProvider_BadPassword(t *testing.T) {
	mgr, err := auth.NewAuthManager(&auth.Config{
		DefaultProvider:    "local",
		EnableAuditLogging: false,
	})
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	info := &auth.ProviderInfo{
		Name:    "local",
		Type:    "local",
		Enabled: true,
		Config: auth.ProviderConfig{
			Local: &auth.LocalConfig{},
		},
	}

	err = mgr.AddProvider(info)
	if err != nil {
		t.Fatalf("AddProvider failed: %v", err)
	}

	err = mgr.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	resp, err := mgr.Authenticate(&auth.AuthRequest{
		Username: "admin",
		Password: "wrong-password",
		Provider: "local",
	})
	if err != nil {
		t.Fatalf("Authenticate returned unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected authentication to fail with wrong password")
	}
}

// TestLocalProvider_NonexistentUser verifies auth failure for unknown users.
func TestLocalProvider_NonexistentUser(t *testing.T) {
	mgr, err := auth.NewAuthManager(&auth.Config{
		DefaultProvider:    "local",
		EnableAuditLogging: false,
	})
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	info := &auth.ProviderInfo{
		Name:    "local",
		Type:    "local",
		Enabled: true,
		Config: auth.ProviderConfig{
			Local: &auth.LocalConfig{},
		},
	}

	err = mgr.AddProvider(info)
	if err != nil {
		t.Fatalf("AddProvider failed: %v", err)
	}

	err = mgr.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	resp, err := mgr.Authenticate(&auth.AuthRequest{
		Username: "nonexistent",
		Password: "password",
		Provider: "local",
	})
	if err != nil {
		t.Fatalf("Authenticate returned unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected authentication to fail for nonexistent user")
	}
}

// TestAuthenticate_NilRequest verifies that nil request returns an error.
func TestAuthenticate_NilRequest(t *testing.T) {
	mgr, err := auth.NewAuthManager(nil)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	_, err = mgr.Authenticate(nil)
	if err == nil {
		t.Fatal("expected error for nil request, got nil")
	}
}

// TestAuthenticate_UnknownProvider verifies that referencing an unregistered
// provider returns an error.
func TestAuthenticate_UnknownProvider(t *testing.T) {
	mgr, err := auth.NewAuthManager(nil)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	_, err = mgr.Authenticate(&auth.AuthRequest{
		Username: "admin",
		Password: "admin",
		Provider: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
}
