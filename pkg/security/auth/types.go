package auth

import (
	"context"
	"time"
)

// Manager defines the interface for authentication management
type Manager interface {
	// Initialize initializes the authentication manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the authentication manager
	Shutdown(ctx context.Context) error

	// Authenticate authenticates a user
	Authenticate(request *AuthRequest) (*AuthResponse, error)

	// ValidateToken validates a token
	ValidateToken(token string) (*TokenInfo, error)

	// RefreshToken refreshes a token
	RefreshToken(refreshToken string) (*TokenResponse, error)

	// RevokeToken revokes a token
	RevokeToken(token string) error

	// GetUserInfo gets information about a user
	GetUserInfo(username string) (*UserInfo, error)

	// ListUsers lists all users
	ListUsers(filter *UserFilter) ([]*UserInfo, error)

	// CreateUser creates a new user
	CreateUser(user *UserInfo) error

	// UpdateUser updates a user
	UpdateUser(user *UserInfo) error

	// DeleteUser deletes a user
	DeleteUser(username string) error

	// AddUserToGroup adds a user to a group
	AddUserToGroup(username, groupName string) error

	// RemoveUserFromGroup removes a user from a group
	RemoveUserFromGroup(username, groupName string) error

	// ListGroups lists all groups
	ListGroups(filter *GroupFilter) ([]*GroupInfo, error)

	// CreateGroup creates a new group
	CreateGroup(group *GroupInfo) error

	// UpdateGroup updates a group
	UpdateGroup(group *GroupInfo) error

	// DeleteGroup deletes a group
	DeleteGroup(groupName string) error

	// GetProviderInfo gets information about an identity provider
	GetProviderInfo(providerName string) (*ProviderInfo, error)

	// ListProviders lists all identity providers
	ListProviders() ([]*ProviderInfo, error)

	// AddProvider adds an identity provider
	AddProvider(provider *ProviderInfo) error

	// UpdateProvider updates an identity provider
	UpdateProvider(provider *ProviderInfo) error

	// RemoveProvider removes an identity provider
	RemoveProvider(providerName string) error
}

// AuthRequest defines an authentication request
type AuthRequest struct {
	// Username is the username for the authentication
	Username string

	// Password is the password for the authentication
	Password string

	// Provider is the identity provider to use
	Provider string

	// ClientID is the client ID for OAuth authentication
	ClientID string

	// ClientSecret is the client secret for OAuth authentication
	ClientSecret string

	// Scope is the scope for OAuth authentication
	Scope string

	// RedirectURI is the redirect URI for OAuth authentication
	RedirectURI string

	// Code is the authorization code for OAuth authentication
	Code string

	// Certificate is the client certificate for certificate authentication
	Certificate []byte

	// MFAToken is the multi-factor authentication token
	MFAToken string

	// IPAddress is the IP address of the client
	IPAddress string

	// UserAgent is the user agent of the client
	UserAgent string
}

// AuthResponse defines an authentication response
type AuthResponse struct {
	// Success indicates whether the authentication was successful
	Success bool

	// Token is the authentication token
	Token string

	// RefreshToken is the refresh token
	RefreshToken string

	// ExpiresIn is the number of seconds until the token expires
	ExpiresIn int

	// TokenType is the type of token
	TokenType string

	// User is the user information
	User *UserInfo

	// MFARequired indicates whether multi-factor authentication is required
	MFARequired bool

	// MFAMethods are the available multi-factor authentication methods
	MFAMethods []string

	// Error is the error message if authentication failed
	Error string

	// ErrorDescription is the error description if authentication failed
	ErrorDescription string
}

// TokenResponse defines a token response
type TokenResponse struct {
	// Token is the authentication token
	Token string

	// RefreshToken is the refresh token
	RefreshToken string

	// ExpiresIn is the number of seconds until the token expires
	ExpiresIn int

	// TokenType is the type of token
	TokenType string
}

// TokenInfo defines token information
type TokenInfo struct {
	// Subject is the subject of the token
	Subject string

	// Username is the username associated with the token
	Username string

	// Issuer is the issuer of the token
	Issuer string

	// IssuedAt is the time when the token was issued
	IssuedAt time.Time

	// ExpiresAt is the time when the token expires
	ExpiresAt time.Time

	// Scope is the scope of the token
	Scope string

	// Claims are the claims in the token
	Claims map[string]interface{}
}

// UserInfo defines user information
type UserInfo struct {
	// Username is the username of the user
	Username string

	// Email is the email address of the user
	Email string

	// FirstName is the first name of the user
	FirstName string

	// LastName is the last name of the user
	LastName string

	// DisplayName is the display name of the user
	DisplayName string

	// Groups are the groups the user belongs to
	Groups []string

	// Roles are the roles assigned to the user
	Roles []string

	// Enabled indicates whether the user is enabled
	Enabled bool

	// Locked indicates whether the user is locked
	Locked bool

	// MFAEnabled indicates whether multi-factor authentication is enabled
	MFAEnabled bool

	// MFAMethods are the multi-factor authentication methods enabled for the user
	MFAMethods []string

	// PasswordLastChanged is the time when the password was last changed
	PasswordLastChanged time.Time

	// LastLogin is the time of the last login
	LastLogin time.Time

	// CreatedAt is the time when the user was created
	CreatedAt time.Time

	// UpdatedAt is the time when the user was last updated
	UpdatedAt time.Time

	// Attributes are additional attributes for the user
	Attributes map[string]interface{}
}

// UserFilter defines a filter for users
type UserFilter struct {
	// Username is the username filter
	Username string

	// Email is the email filter
	Email string

	// Group is the group filter
	Group string

	// Role is the role filter
	Role string

	// Enabled is the enabled filter
	Enabled *bool

	// Locked is the locked filter
	Locked *bool

	// MFAEnabled is the MFA enabled filter
	MFAEnabled *bool

	// Limit is the maximum number of users to return
	Limit int

	// Offset is the offset for pagination
	Offset int
}

// GroupInfo defines group information
type GroupInfo struct {
	// Name is the name of the group
	Name string

	// Description is the description of the group
	Description string

	// Members are the members of the group
	Members []string

	// Roles are the roles assigned to the group
	Roles []string

	// CreatedAt is the time when the group was created
	CreatedAt time.Time

	// UpdatedAt is the time when the group was last updated
	UpdatedAt time.Time

	// Attributes are additional attributes for the group
	Attributes map[string]interface{}
}

// GroupFilter defines a filter for groups
type GroupFilter struct {
	// Name is the name filter
	Name string

	// Member is the member filter
	Member string

	// Role is the role filter
	Role string

	// Limit is the maximum number of groups to return
	Limit int

	// Offset is the offset for pagination
	Offset int
}

// ProviderInfo defines identity provider information
type ProviderInfo struct {
	// Name is the name of the provider
	Name string

	// Type is the type of provider
	Type string

	// Enabled indicates whether the provider is enabled
	Enabled bool

	// Priority is the priority of the provider
	Priority int

	// Config is the configuration for the provider
	Config ProviderConfig

	// CreatedAt is the time when the provider was created
	CreatedAt time.Time

	// UpdatedAt is the time when the provider was last updated
	UpdatedAt time.Time
}

// ProviderConfig defines the configuration for an identity provider
type ProviderConfig struct {
	// Local is the configuration for local authentication
	Local *LocalConfig

	// LDAP is the configuration for LDAP authentication
	LDAP *LDAPConfig

	// OAuth is the configuration for OAuth authentication
	OAuth *OAuthConfig

	// SAML is the configuration for SAML authentication
	SAML *SAMLConfig

	// RADIUS is the configuration for RADIUS authentication
	RADIUS *RADIUSConfig

	// Certificate is the configuration for certificate authentication
	Certificate *CertificateConfig
}

// LocalConfig defines the configuration for local authentication
type LocalConfig struct {
	// PasswordPolicy is the password policy
	PasswordPolicy PasswordPolicy

	// MFAEnabled indicates whether multi-factor authentication is enabled
	MFAEnabled bool

	// MFAMethods are the multi-factor authentication methods
	MFAMethods []string
}

// PasswordPolicy defines a password policy
type PasswordPolicy struct {
	// MinLength is the minimum length of passwords
	MinLength int

	// RequireUppercase indicates whether passwords must contain uppercase letters
	RequireUppercase bool

	// RequireLowercase indicates whether passwords must contain lowercase letters
	RequireLowercase bool

	// RequireNumbers indicates whether passwords must contain numbers
	RequireNumbers bool

	// RequireSpecial indicates whether passwords must contain special characters
	RequireSpecial bool

	// MaxAge is the maximum age of passwords in days
	MaxAge int

	// HistoryCount is the number of previous passwords to remember
	HistoryCount int
}

// LDAPConfig defines the configuration for LDAP authentication
type LDAPConfig struct {
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
}

// OAuthConfig defines the configuration for OAuth authentication
type OAuthConfig struct {
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
}

// SAMLConfig defines the configuration for SAML authentication
type SAMLConfig struct {
	// MetadataURL is the URL of the SAML metadata
	MetadataURL string

	// EntityID is the entity ID
	EntityID string

	// AssertionConsumerServiceURL is the assertion consumer service URL
	AssertionConsumerServiceURL string

	// SignAuthnRequests indicates whether to sign authentication requests
	SignAuthnRequests bool

	// SigningCert is the signing certificate
	SigningCert string

	// SigningKey is the signing key
	SigningKey string

	// EncryptionCert is the encryption certificate
	EncryptionCert string

	// EncryptionKey is the encryption key
	EncryptionKey string

	// UserIDAttribute is the attribute for user IDs
	UserIDAttribute string

	// UserAttributes are the attributes to retrieve for users
	UserAttributes map[string]string
}

// RADIUSConfig defines the configuration for RADIUS authentication
type RADIUSConfig struct {
	// Server is the RADIUS server
	Server string

	// Port is the RADIUS port
	Port int

	// Secret is the RADIUS secret
	Secret string

	// Timeout is the timeout in seconds
	Timeout int

	// Retries is the number of retries
	Retries int

	// NASIdentifier is the NAS identifier
	NASIdentifier string
}

// CertificateConfig defines the configuration for certificate authentication
type CertificateConfig struct {
	// CACert is the CA certificate
	CACert string

	// UserCertAttribute is the attribute for user certificates
	UserCertAttribute string

	// UserIDAttribute is the attribute for user IDs
	UserIDAttribute string

	// VerifyClient indicates whether to verify the client
	VerifyClient bool
}

// Provider defines the interface for authentication providers
type Provider interface {
	// Initialize initializes the provider
	Initialize(ctx context.Context) error

	// Shutdown shuts down the provider
	Shutdown(ctx context.Context) error

	// Authenticate authenticates a user
	Authenticate(request *AuthRequest) (*AuthResponse, error)

	// ValidateToken validates a token
	ValidateToken(token string) (*TokenInfo, error)

	// RefreshToken refreshes a token
	RefreshToken(refreshToken string) (*TokenResponse, error)

	// RevokeToken revokes a token
	RevokeToken(token string) error

	// GetUserInfo gets information about a user
	GetUserInfo(username string) (*UserInfo, error)

	// ListUsers lists all users
	ListUsers(filter *UserFilter) ([]*UserInfo, error)

	// CreateUser creates a new user
	CreateUser(user *UserInfo) error

	// UpdateUser updates a user
	UpdateUser(user *UserInfo) error

	// DeleteUser deletes a user
	DeleteUser(username string) error

	// AddUserToGroup adds a user to a group
	AddUserToGroup(username, groupName string) error

	// RemoveUserFromGroup removes a user from a group
	RemoveUserFromGroup(username, groupName string) error

	// ListGroups lists all groups
	ListGroups(filter *GroupFilter) ([]*GroupInfo, error)

	// CreateGroup creates a new group
	CreateGroup(group *GroupInfo) error

	// UpdateGroup updates a group
	UpdateGroup(group *GroupInfo) error

	// DeleteGroup deletes a group
	DeleteGroup(groupName string) error

	// GetInfo gets information about the provider
	GetInfo() *ProviderInfo
}

// AuditEvent defines an audit event
type AuditEvent struct {
	// Time is the time of the event
	Time time.Time

	// Type is the type of event
	Type string

	// Username is the username associated with the event
	Username string

	// Provider is the identity provider associated with the event
	Provider string

	// IPAddress is the IP address associated with the event
	IPAddress string

	// UserAgent is the user agent associated with the event
	UserAgent string

	// Resource is the resource associated with the event
	Resource string

	// Action is the action associated with the event
	Action string

	// Result is the result of the event
	Result string

	// Details are additional details for the event
	Details map[string]interface{}
}

// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	// LogEvent logs an audit event
	LogEvent(event *AuditEvent) error

	// GetEvents gets audit events
	GetEvents(filter *AuditEventFilter) ([]*AuditEvent, error)
}

// AuditEventFilter defines a filter for audit events
type AuditEventFilter struct {
	// StartTime is the start time for the filter
	StartTime time.Time

	// EndTime is the end time for the filter
	EndTime time.Time

	// Type is the type filter
	Type string

	// Username is the username filter
	Username string

	// Provider is the provider filter
	Provider string

	// IPAddress is the IP address filter
	IPAddress string

	// Resource is the resource filter
	Resource string

	// Action is the action filter
	Action string

	// Result is the result filter
	Result string

	// Limit is the maximum number of events to return
	Limit int

	// Offset is the offset for pagination
	Offset int
}
