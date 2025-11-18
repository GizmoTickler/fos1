package providers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/security/auth"
)

// LDAPProvider implements the auth.Provider interface for LDAP authentication
type LDAPProvider struct {
	// Configuration
	config *LDAPConfig

	// Tokens
	tokens        map[string]*tokenData
	refreshTokens map[string]string

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
}

// LDAPConfig holds the configuration for the LDAP authentication provider
type LDAPConfig struct {
	// Name is the name of the provider
	Name string

	// Enabled indicates whether the provider is enabled
	Enabled bool

	// Priority is the priority of the provider
	Priority int

	// URL is the URL of the LDAP server
	URL string

	// BindDN is the bind DN for the LDAP server
	BindDN string

	// BindPassword is the bind password for the LDAP server
	BindPassword string

	// UserBaseDN is the base DN for users
	UserBaseDN string

	// UserFilter is the filter for users
	UserFilter string

	// GroupBaseDN is the base DN for groups
	GroupBaseDN string

	// GroupFilter is the filter for groups
	GroupFilter string

	// GroupMemberAttribute is the attribute for group members
	GroupMemberAttribute string

	// UserAttributes are the attributes to retrieve for users
	UserAttributes map[string]string

	// StartTLS indicates whether to use StartTLS
	StartTLS bool

	// InsecureSkipVerify indicates whether to skip TLS verification
	InsecureSkipVerify bool

	// CACert is the CA certificate for TLS
	CACert string

	// TokenExpiration is the token expiration time
	TokenExpiration time.Duration

	// RefreshTokenExpiration is the refresh token expiration time
	RefreshTokenExpiration time.Duration
}

// NewLDAPProvider creates a new LDAP authentication provider
func NewLDAPProvider(config *LDAPConfig) (*LDAPProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("LDAP configuration is required")
	}

	if config.URL == "" {
		return nil, fmt.Errorf("LDAP URL is required")
	}

	if config.UserBaseDN == "" {
		return nil, fmt.Errorf("LDAP user base DN is required")
	}

	if config.UserFilter == "" {
		config.UserFilter = "(uid=%s)"
	}

	if config.GroupBaseDN == "" {
		config.GroupBaseDN = config.UserBaseDN
	}

	if config.GroupFilter == "" {
		config.GroupFilter = "(objectClass=groupOfNames)"
	}

	if config.GroupMemberAttribute == "" {
		config.GroupMemberAttribute = "member"
	}

	if config.UserAttributes == nil {
		config.UserAttributes = map[string]string{
			"uid":          "username",
			"mail":         "email",
			"givenName":    "firstName",
			"sn":           "lastName",
			"displayName":  "displayName",
			"cn":           "commonName",
			"userPassword": "password",
		}
	}

	if config.TokenExpiration == 0 {
		config.TokenExpiration = 24 * time.Hour
	}

	if config.RefreshTokenExpiration == 0 {
		config.RefreshTokenExpiration = 7 * 24 * time.Hour
	}

	// Create context for management
	ctx, cancel := context.WithCancel(context.Background())

	return &LDAPProvider{
		config:        config,
		tokens:        make(map[string]*tokenData),
		refreshTokens: make(map[string]string),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// Initialize initializes the provider
func (p *LDAPProvider) Initialize(ctx context.Context) error {
	klog.Info("Initializing LDAP authentication provider")

	// Test the LDAP connection
	conn, err := p.connect()
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	klog.Info("LDAP authentication provider initialized successfully")
	return nil
}

// Shutdown shuts down the provider
func (p *LDAPProvider) Shutdown(ctx context.Context) error {
	klog.Info("Shutting down LDAP authentication provider")
	p.cancel()
	return nil
}

// Authenticate authenticates a user
func (p *LDAPProvider) Authenticate(request *auth.AuthRequest) (*auth.AuthResponse, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if request == nil {
		return nil, fmt.Errorf("authentication request is nil")
	}

	if request.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	if request.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Connect to the LDAP server
	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Bind with the service account
	if p.config.BindDN != "" && p.config.BindPassword != "" {
		if err := conn.Bind(p.config.BindDN, p.config.BindPassword); err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for the user
	userFilter := fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(request.Username))
	searchRequest := ldap.NewSearchRequest(
		p.config.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		ldapAttributeNames(p.config.UserAttributes),
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) != 1 {
		return &auth.AuthResponse{
			Success:          false,
			Error:            "invalid_credentials",
			ErrorDescription: "Invalid username or password",
		}, nil
	}

	userEntry := searchResult.Entries[0]

	// Bind with the user's credentials
	if err := conn.Bind(userEntry.DN, request.Password); err != nil {
		return &auth.AuthResponse{
			Success:          false,
			Error:            "invalid_credentials",
			ErrorDescription: "Invalid username or password",
		}, nil
	}

	// Get user information
	user := p.mapLDAPEntryToUser(userEntry)

	// Get user groups
	groups, err := p.getUserGroups(conn, userEntry.DN)
	if err != nil {
		klog.Warningf("Failed to get user groups: %v", err)
	}
	user.Groups = groups

	// Generate tokens
	token, refreshToken, err := p.generateTokens(user.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &auth.AuthResponse{
		Success:      true,
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresIn:    int(p.config.TokenExpiration.Seconds()),
		TokenType:    "Bearer",
		User:         user,
	}, nil
}

// ValidateToken validates a token
func (p *LDAPProvider) ValidateToken(token string) (*auth.TokenInfo, error) {
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
func (p *LDAPProvider) RefreshToken(refreshToken string) (*auth.TokenResponse, error) {
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
func (p *LDAPProvider) RevokeToken(token string) error {
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
func (p *LDAPProvider) GetUserInfo(username string) (*auth.UserInfo, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Connect to the LDAP server
	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Bind with the service account
	if p.config.BindDN != "" && p.config.BindPassword != "" {
		if err := conn.Bind(p.config.BindDN, p.config.BindPassword); err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for the user
	userFilter := fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		p.config.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		ldapAttributeNames(p.config.UserAttributes),
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) != 1 {
		return nil, fmt.Errorf("user not found")
	}

	userEntry := searchResult.Entries[0]

	// Get user information
	user := p.mapLDAPEntryToUser(userEntry)

	// Get user groups
	groups, err := p.getUserGroups(conn, userEntry.DN)
	if err != nil {
		klog.Warningf("Failed to get user groups: %v", err)
	}
	user.Groups = groups

	return user, nil
}

// ListUsers lists all users
func (p *LDAPProvider) ListUsers(filter *auth.UserFilter) ([]*auth.UserInfo, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if filter == nil {
		filter = &auth.UserFilter{}
	}

	// Connect to the LDAP server
	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Bind with the service account
	if p.config.BindDN != "" && p.config.BindPassword != "" {
		if err := conn.Bind(p.config.BindDN, p.config.BindPassword); err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for users
	userFilter := "(objectClass=*)"
	if filter.Username != "" {
		userFilter = fmt.Sprintf("(&%s%s)", userFilter, fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(filter.Username)))
	}
	if filter.Email != "" {
		userFilter = fmt.Sprintf("(&%s(mail=%s))", userFilter, ldap.EscapeFilter(filter.Email))
	}

	searchRequest := ldap.NewSearchRequest(
		p.config.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		ldapAttributeNames(p.config.UserAttributes),
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for users: %w", err)
	}

	var users []*auth.UserInfo
	for _, userEntry := range searchResult.Entries {
		// Get user information
		user := p.mapLDAPEntryToUser(userEntry)

		// Get user groups
		groups, err := p.getUserGroups(conn, userEntry.DN)
		if err != nil {
			klog.Warningf("Failed to get user groups: %v", err)
		}
		user.Groups = groups

		// Apply group filter
		if filter.Group != "" {
			found := false
			for _, group := range user.Groups {
				if group == filter.Group {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		users = append(users, user)
	}

	// Apply pagination
	if filter.Limit > 0 && filter.Offset >= 0 && filter.Offset < len(users) {
		end := filter.Offset + filter.Limit
		if end > len(users) {
			end = len(users)
		}
		users = users[filter.Offset:end]
	}

	return users, nil
}

// CreateUser creates a new user
func (p *LDAPProvider) CreateUser(user *auth.UserInfo) error {
	return fmt.Errorf("creating users is not supported by the LDAP provider")
}

// UpdateUser updates a user
func (p *LDAPProvider) UpdateUser(user *auth.UserInfo) error {
	return fmt.Errorf("updating users is not supported by the LDAP provider")
}

// DeleteUser deletes a user
func (p *LDAPProvider) DeleteUser(username string) error {
	return fmt.Errorf("deleting users is not supported by the LDAP provider")
}

// AddUserToGroup adds a user to a group
func (p *LDAPProvider) AddUserToGroup(username, groupName string) error {
	return fmt.Errorf("adding users to groups is not supported by the LDAP provider")
}

// RemoveUserFromGroup removes a user from a group
func (p *LDAPProvider) RemoveUserFromGroup(username, groupName string) error {
	return fmt.Errorf("removing users from groups is not supported by the LDAP provider")
}

// ListGroups lists all groups
func (p *LDAPProvider) ListGroups(filter *auth.GroupFilter) ([]*auth.GroupInfo, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if filter == nil {
		filter = &auth.GroupFilter{}
	}

	// Connect to the LDAP server
	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Bind with the service account
	if p.config.BindDN != "" && p.config.BindPassword != "" {
		if err := conn.Bind(p.config.BindDN, p.config.BindPassword); err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for groups
	groupFilter := p.config.GroupFilter
	if filter.Name != "" {
		groupFilter = fmt.Sprintf("(&%s(cn=%s))", groupFilter, ldap.EscapeFilter(filter.Name))
	}

	searchRequest := ldap.NewSearchRequest(
		p.config.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{"cn", "description", p.config.GroupMemberAttribute},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	var groups []*auth.GroupInfo
	for _, groupEntry := range searchResult.Entries {
		// Get group information
		group := p.mapLDAPEntryToGroup(groupEntry)

		// Apply member filter
		if filter.Member != "" {
			// Get the user's DN
			userDN, err := p.getUserDN(conn, filter.Member)
			if err != nil {
				klog.Warningf("Failed to get user DN: %v", err)
				continue
			}

			// Check if the user is a member of the group
			found := false
			for _, member := range group.Members {
				if member == filter.Member {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		groups = append(groups, group)
	}

	// Apply pagination
	if filter.Limit > 0 && filter.Offset >= 0 && filter.Offset < len(groups) {
		end := filter.Offset + filter.Limit
		if end > len(groups) {
			end = len(groups)
		}
		groups = groups[filter.Offset:end]
	}

	return groups, nil
}

// CreateGroup creates a new group
func (p *LDAPProvider) CreateGroup(group *auth.GroupInfo) error {
	return fmt.Errorf("creating groups is not supported by the LDAP provider")
}

// UpdateGroup updates a group
func (p *LDAPProvider) UpdateGroup(group *auth.GroupInfo) error {
	return fmt.Errorf("updating groups is not supported by the LDAP provider")
}

// DeleteGroup deletes a group
func (p *LDAPProvider) DeleteGroup(groupName string) error {
	return fmt.Errorf("deleting groups is not supported by the LDAP provider")
}

// GetInfo gets information about the provider
func (p *LDAPProvider) GetInfo() *auth.ProviderInfo {
	return &auth.ProviderInfo{
		Name:      p.config.Name,
		Type:      "ldap",
		Enabled:   p.config.Enabled,
		Priority:  p.config.Priority,
		CreatedAt: time.Time{},
		UpdatedAt: time.Time{},
		Config: auth.ProviderConfig{
			LDAP: &auth.LDAPConfig{
				URL:                 p.config.URL,
				BindDN:              p.config.BindDN,
				BindPassword:        p.config.BindPassword,
				UserBaseDN:          p.config.UserBaseDN,
				UserFilter:          p.config.UserFilter,
				GroupBaseDN:         p.config.GroupBaseDN,
				GroupFilter:         p.config.GroupFilter,
				GroupMemberAttribute: p.config.GroupMemberAttribute,
				UserAttributes:      p.config.UserAttributes,
				StartTLS:            p.config.StartTLS,
				InsecureSkipVerify:  p.config.InsecureSkipVerify,
				CACert:              p.config.CACert,
			},
		},
	}
}

// connect connects to the LDAP server
func (p *LDAPProvider) connect() (*ldap.Conn, error) {
	// Connect to the LDAP server
	conn, err := ldap.DialURL(p.config.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Configure TLS
	if p.config.StartTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: p.config.InsecureSkipVerify,
		}

		// Add CA certificate if provided
		if p.config.CACert != "" {
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM([]byte(p.config.CACert)) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = certPool
		}

		// Start TLS
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	return conn, nil
}

// getUserDN gets the DN of a user
func (p *LDAPProvider) getUserDN(conn *ldap.Conn, username string) (string, error) {
	// Search for the user
	userFilter := fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		p.config.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		[]string{"dn"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("user not found")
	}

	return searchResult.Entries[0].DN, nil
}

// getUserGroups gets the groups a user belongs to
func (p *LDAPProvider) getUserGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	// Search for groups the user belongs to
	groupFilter := fmt.Sprintf("(&%s(%s=%s))", p.config.GroupFilter, p.config.GroupMemberAttribute, ldap.EscapeFilter(userDN))
	searchRequest := ldap.NewSearchRequest(
		p.config.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{"cn"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	var groups []string
	for _, groupEntry := range searchResult.Entries {
		groups = append(groups, groupEntry.GetAttributeValue("cn"))
	}

	return groups, nil
}

// mapLDAPEntryToUser maps an LDAP entry to a user
func (p *LDAPProvider) mapLDAPEntryToUser(entry *ldap.Entry) *auth.UserInfo {
	user := &auth.UserInfo{
		Enabled:    true,
		Attributes: make(map[string]interface{}),
	}

	// Map attributes
	for ldapAttr, userAttr := range p.config.UserAttributes {
		value := entry.GetAttributeValue(ldapAttr)
		if value == "" {
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

	return user
}

// mapLDAPEntryToGroup maps an LDAP entry to a group
func (p *LDAPProvider) mapLDAPEntryToGroup(entry *ldap.Entry) *auth.GroupInfo {
	group := &auth.GroupInfo{
		Name:        entry.GetAttributeValue("cn"),
		Description: entry.GetAttributeValue("description"),
		Attributes:  make(map[string]interface{}),
	}

	// Get members
	memberValues := entry.GetAttributeValues(p.config.GroupMemberAttribute)
	for _, memberDN := range memberValues {
		// Extract the username from the DN
		// This is a simplified implementation
		// In a real implementation, you would extract the username from the DN
		// based on the user filter
		parts := ldap.ParseDN(memberDN)
		if len(parts) > 0 {
			for _, part := range parts {
				if part.Type == "uid" {
					group.Members = append(group.Members, part.Value)
					break
				}
			}
		}
	}

	return group
}

// generateTokens generates a token and refresh token
func (p *LDAPProvider) generateTokens(username string) (string, string, error) {
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

// ldapAttributeNames gets the LDAP attribute names from a map
func ldapAttributeNames(attributes map[string]string) []string {
	var names []string
	for name := range attributes {
		names = append(names, name)
	}
	return names
}
