package providers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/security/auth"
)

// OAuthProvider implements the auth.Provider interface for OAuth authentication
type OAuthProvider struct {
	// Configuration
	config *OAuthConfig

	// OAuth2 configuration
	oauth2Config *oauth2.Config

	// Tokens
	tokens        map[string]*tokenData
	refreshTokens map[string]string

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
}

// OAuthConfig holds the configuration for the OAuth authentication provider
type OAuthConfig struct {
	// Name is the name of the provider
	Name string

	// Enabled indicates whether the provider is enabled
	Enabled bool

	// Priority is the priority of the provider
	Priority int

	// ProviderType is the type of OAuth provider
	ProviderType string

	// ClientID is the client ID
	ClientID string

	// ClientSecret is the client secret
	ClientSecret string

	// AuthorizationURL is the authorization URL
	AuthorizationURL string

	// TokenURL is the token URL
	TokenURL string

	// UserInfoURL is the user info URL
	UserInfoURL string

	// RedirectURL is the redirect URL
	RedirectURL string

	// Scopes are the scopes to request
	Scopes []string

	// UserIDAttribute is the attribute for user IDs
	UserIDAttribute string

	// UserAttributes are the attributes to retrieve for users
	UserAttributes map[string]string

	// TokenExpiration is the token expiration time
	TokenExpiration time.Duration

	// RefreshTokenExpiration is the refresh token expiration time
	RefreshTokenExpiration time.Duration
}

// NewOAuthProvider creates a new OAuth authentication provider
func NewOAuthProvider(config *OAuthConfig) (*OAuthProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("OAuth configuration is required")
	}

	if config.ProviderType == "" {
		return nil, fmt.Errorf("OAuth provider type is required")
	}

	if config.ClientID == "" {
		return nil, fmt.Errorf("OAuth client ID is required")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("OAuth client secret is required")
	}

	if config.AuthorizationURL == "" {
		return nil, fmt.Errorf("OAuth authorization URL is required")
	}

	if config.TokenURL == "" {
		return nil, fmt.Errorf("OAuth token URL is required")
	}

	if config.UserInfoURL == "" {
		return nil, fmt.Errorf("OAuth user info URL is required")
	}

	if config.RedirectURL == "" {
		return nil, fmt.Errorf("OAuth redirect URL is required")
	}

	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	}

	if config.UserIDAttribute == "" {
		config.UserIDAttribute = "sub"
	}

	if config.UserAttributes == nil {
		config.UserAttributes = map[string]string{
			"sub":         "username",
			"email":       "email",
			"given_name":  "firstName",
			"family_name": "lastName",
			"name":        "displayName",
		}
	}

	if config.TokenExpiration == 0 {
		config.TokenExpiration = 24 * time.Hour
	}

	if config.RefreshTokenExpiration == 0 {
		config.RefreshTokenExpiration = 7 * 24 * time.Hour
	}

	// Create OAuth2 configuration
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizationURL,
			TokenURL: config.TokenURL,
		},
		RedirectURL: config.RedirectURL,
		Scopes:      config.Scopes,
	}

	// Create context for management
	ctx, cancel := context.WithCancel(context.Background())

	return &OAuthProvider{
		config:        config,
		oauth2Config:  oauth2Config,
		tokens:        make(map[string]*tokenData),
		refreshTokens: make(map[string]string),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// Initialize initializes the provider
func (p *OAuthProvider) Initialize(ctx context.Context) error {
	klog.Info("Initializing OAuth authentication provider")
	klog.Info("OAuth authentication provider initialized successfully")
	return nil
}

// Shutdown shuts down the provider
func (p *OAuthProvider) Shutdown(ctx context.Context) error {
	klog.Info("Shutting down OAuth authentication provider")
	p.cancel()
	return nil
}

// Authenticate authenticates a user
func (p *OAuthProvider) Authenticate(request *auth.AuthRequest) (*auth.AuthResponse, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if request == nil {
		return nil, fmt.Errorf("authentication request is nil")
	}

	// Check if this is an authorization code flow
	if request.Code != "" {
		// Exchange the authorization code for a token
		token, err := p.oauth2Config.Exchange(p.ctx, request.Code)
		if err != nil {
			return &auth.AuthResponse{
				Success:          false,
				Error:            "invalid_grant",
				ErrorDescription: "Invalid authorization code",
			}, nil
		}

		// Get user information
		user, err := p.getUserInfo(token.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get user info: %w", err)
		}

		// Generate tokens
		accessToken, refreshToken, err := p.generateTokens(user.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to generate tokens: %w", err)
		}

		return &auth.AuthResponse{
			Success:      true,
			Token:        accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int(p.config.TokenExpiration.Seconds()),
			TokenType:    "Bearer",
			User:         user,
		}, nil
	}

	// For other authentication methods, return an error
	return &auth.AuthResponse{
		Success:          false,
		Error:            "unsupported_grant_type",
		ErrorDescription: "Only authorization code flow is supported",
	}, nil
}

// ValidateToken validates a token
func (p *OAuthProvider) ValidateToken(token string) (*auth.TokenInfo, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	// Check if the token exists
	tokenData, exists := p.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if the token has expired
	if time.Now().After(tokenData.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	// Get user information
	user, err := p.GetUserInfo(tokenData.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return &auth.TokenInfo{
		Subject:   tokenData.Username,
		Username:  tokenData.Username,
		Issuer:    p.config.Name,
		IssuedAt:  tokenData.ExpiresAt.Add(-p.config.TokenExpiration),
		ExpiresAt: tokenData.ExpiresAt,
		Claims: map[string]interface{}{
			"username": tokenData.Username,
			"groups":   user.Groups,
			"roles":    user.Roles,
		},
	}, nil
}

// RefreshToken refreshes a token
func (p *OAuthProvider) RefreshToken(refreshToken string) (*auth.TokenResponse, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	// Check if the refresh token exists
	token, exists := p.refreshTokens[refreshToken]
	if !exists {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if the token exists
	tokenData, exists := p.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}

	// Generate new tokens
	newToken, newRefreshToken, err := p.generateTokens(tokenData.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Revoke the old tokens
	delete(p.tokens, token)
	delete(p.refreshTokens, refreshToken)

	return &auth.TokenResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int(p.config.TokenExpiration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// RevokeToken revokes a token
func (p *OAuthProvider) RevokeToken(token string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if token == "" {
		return fmt.Errorf("token is required")
	}

	// Check if the token exists
	tokenData, exists := p.tokens[token]
	if !exists {
		return fmt.Errorf("invalid token")
	}

	// Revoke the token
	delete(p.tokens, token)
	delete(p.refreshTokens, tokenData.RefreshToken)

	return nil
}

// GetUserInfo gets information about a user
func (p *OAuthProvider) GetUserInfo(username string) (*auth.UserInfo, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// This is a simplified implementation
	// In a real implementation, you would get the user information from the OAuth provider
	// using the user's access token
	user := &auth.UserInfo{
		Username:    username,
		Email:       fmt.Sprintf("%s@example.com", username),
		DisplayName: username,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Attributes:  make(map[string]interface{}),
	}

	return user, nil
}

// ListUsers lists all users
func (p *OAuthProvider) ListUsers(filter *auth.UserFilter) ([]*auth.UserInfo, error) {
	return nil, fmt.Errorf("listing users is not supported by the OAuth provider")
}

// CreateUser creates a new user
func (p *OAuthProvider) CreateUser(user *auth.UserInfo) error {
	return fmt.Errorf("creating users is not supported by the OAuth provider")
}

// UpdateUser updates a user
func (p *OAuthProvider) UpdateUser(user *auth.UserInfo) error {
	return fmt.Errorf("updating users is not supported by the OAuth provider")
}

// DeleteUser deletes a user
func (p *OAuthProvider) DeleteUser(username string) error {
	return fmt.Errorf("deleting users is not supported by the OAuth provider")
}

// AddUserToGroup adds a user to a group
func (p *OAuthProvider) AddUserToGroup(username, groupName string) error {
	return fmt.Errorf("adding users to groups is not supported by the OAuth provider")
}

// RemoveUserFromGroup removes a user from a group
func (p *OAuthProvider) RemoveUserFromGroup(username, groupName string) error {
	return fmt.Errorf("removing users from groups is not supported by the OAuth provider")
}

// ListGroups lists all groups
func (p *OAuthProvider) ListGroups(filter *auth.GroupFilter) ([]*auth.GroupInfo, error) {
	return nil, fmt.Errorf("listing groups is not supported by the OAuth provider")
}

// CreateGroup creates a new group
func (p *OAuthProvider) CreateGroup(group *auth.GroupInfo) error {
	return fmt.Errorf("creating groups is not supported by the OAuth provider")
}

// UpdateGroup updates a group
func (p *OAuthProvider) UpdateGroup(group *auth.GroupInfo) error {
	return fmt.Errorf("updating groups is not supported by the OAuth provider")
}

// DeleteGroup deletes a group
func (p *OAuthProvider) DeleteGroup(groupName string) error {
	return fmt.Errorf("deleting groups is not supported by the OAuth provider")
}

// GetInfo gets information about the provider
func (p *OAuthProvider) GetInfo() *auth.ProviderInfo {
	return &auth.ProviderInfo{
		Name:      p.config.Name,
		Type:      "oauth",
		Enabled:   p.config.Enabled,
		Priority:  p.config.Priority,
		CreatedAt: time.Time{},
		UpdatedAt: time.Time{},
		Config: auth.ProviderConfig{
			OAuth: &auth.OAuthConfig{
				ProviderType:    p.config.ProviderType,
				ClientID:        p.config.ClientID,
				ClientSecret:    p.config.ClientSecret,
				AuthorizationURL: p.config.AuthorizationURL,
				TokenURL:        p.config.TokenURL,
				UserInfoURL:     p.config.UserInfoURL,
				RedirectURL:     p.config.RedirectURL,
				Scopes:          p.config.Scopes,
				UserIDAttribute: p.config.UserIDAttribute,
				UserAttributes:  p.config.UserAttributes,
			},
		},
	}
}

// getUserInfo gets user information from the OAuth provider
func (p *OAuthProvider) getUserInfo(accessToken string) (*auth.UserInfo, error) {
	// Create request to user info endpoint
	req, err := http.NewRequest("GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response body
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse response body: %w", err)
	}

	// Get user ID
	userID, ok := data[p.config.UserIDAttribute].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("user ID not found in response")
	}

	// Create user info
	user := &auth.UserInfo{
		Username:   userID,
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Attributes: make(map[string]interface{}),
	}

	// Map attributes
	for oauthAttr, userAttr := range p.config.UserAttributes {
		value, ok := data[oauthAttr].(string)
		if !ok || value == "" {
			continue
		}

		switch userAttr {
		case "username":
			user.Username = value
		case "email":
			user.Email = value
		case "firstName":
			user.FirstName = value
		case "lastName":
			user.LastName = value
		case "displayName":
			user.DisplayName = value
		default:
			user.Attributes[userAttr] = value
		}
	}

	// Set default display name if not set
	if user.DisplayName == "" {
		if user.FirstName != "" && user.LastName != "" {
			user.DisplayName = user.FirstName + " " + user.LastName
		} else if user.FirstName != "" {
			user.DisplayName = user.FirstName
		} else if user.LastName != "" {
			user.DisplayName = user.LastName
		} else {
			user.DisplayName = user.Username
		}
	}

	// Get groups
	groups, ok := data["groups"].([]interface{})
	if ok {
		for _, group := range groups {
			groupName, ok := group.(string)
			if ok && groupName != "" {
				user.Groups = append(user.Groups, groupName)
			}
		}
	}

	// Get roles
	roles, ok := data["roles"].([]interface{})
	if ok {
		for _, role := range roles {
			roleName, ok := role.(string)
			if ok && roleName != "" {
				user.Roles = append(user.Roles, roleName)
			}
		}
	}

	return user, nil
}

// generateTokens generates a token and refresh token
func (p *OAuthProvider) generateTokens(username string) (string, string, error) {
	// Generate a random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Generate a random refresh token
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	// Store the tokens
	p.tokens[token] = &tokenData{
		Username:     username,
		ExpiresAt:    time.Now().Add(p.config.TokenExpiration),
		RefreshToken: refreshToken,
	}
	p.refreshTokens[refreshToken] = token

	return token, refreshToken, nil
}

// GetAuthorizationURL gets the authorization URL for OAuth authentication
func (p *OAuthProvider) GetAuthorizationURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state)
}
