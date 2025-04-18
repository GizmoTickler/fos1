package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthProvider defines an authentication provider
type AuthProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthProviderSpec   `json:"spec"`
	Status AuthProviderStatus `json:"status,omitempty"`
}

// AuthProviderSpec defines the desired state of an authentication provider
type AuthProviderSpec struct {
	// Type is the type of authentication provider
	Type string `json:"type"`

	// Enabled indicates whether the provider is enabled
	Enabled bool `json:"enabled,omitempty"`

	// Priority is the priority of the provider
	Priority int `json:"priority,omitempty"`

	// Local is the configuration for local authentication
	Local *LocalAuthConfig `json:"local,omitempty"`

	// LDAP is the configuration for LDAP authentication
	LDAP *LDAPAuthConfig `json:"ldap,omitempty"`

	// OAuth is the configuration for OAuth authentication
	OAuth *OAuthAuthConfig `json:"oauth,omitempty"`

	// SAML is the configuration for SAML authentication
	SAML *SAMLAuthConfig `json:"saml,omitempty"`

	// RADIUS is the configuration for RADIUS authentication
	RADIUS *RADIUSAuthConfig `json:"radius,omitempty"`

	// Certificate is the configuration for certificate authentication
	Certificate *CertificateAuthConfig `json:"certificate,omitempty"`

	// Resources are the resource requirements
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector is the node selector for deployment
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// LocalAuthConfig defines the configuration for local authentication
type LocalAuthConfig struct {
	// PasswordPolicy is the password policy
	PasswordPolicy PasswordPolicyConfig `json:"passwordPolicy,omitempty"`

	// MFAEnabled indicates whether multi-factor authentication is enabled
	MFAEnabled bool `json:"mfaEnabled,omitempty"`

	// MFAMethods are the multi-factor authentication methods
	MFAMethods []string `json:"mfaMethods,omitempty"`
}

// PasswordPolicyConfig defines a password policy
type PasswordPolicyConfig struct {
	// MinLength is the minimum length of passwords
	MinLength int `json:"minLength,omitempty"`

	// RequireUppercase indicates whether passwords must contain uppercase letters
	RequireUppercase bool `json:"requireUppercase,omitempty"`

	// RequireLowercase indicates whether passwords must contain lowercase letters
	RequireLowercase bool `json:"requireLowercase,omitempty"`

	// RequireNumbers indicates whether passwords must contain numbers
	RequireNumbers bool `json:"requireNumbers,omitempty"`

	// RequireSpecial indicates whether passwords must contain special characters
	RequireSpecial bool `json:"requireSpecial,omitempty"`

	// MaxAge is the maximum age of passwords in days
	MaxAge int `json:"maxAge,omitempty"`

	// HistoryCount is the number of previous passwords to remember
	HistoryCount int `json:"historyCount,omitempty"`
}

// LDAPAuthConfig defines the configuration for LDAP authentication
type LDAPAuthConfig struct {
	// URL is the URL of the LDAP server
	URL string `json:"url"`

	// BindDN is the bind DN for the LDAP server
	BindDN string `json:"bindDN,omitempty"`

	// BindPassword is the bind password for the LDAP server
	BindPassword string `json:"bindPassword,omitempty"`

	// UserBaseDN is the base DN for users
	UserBaseDN string `json:"userBaseDN"`

	// UserFilter is the filter for users
	UserFilter string `json:"userFilter,omitempty"`

	// GroupBaseDN is the base DN for groups
	GroupBaseDN string `json:"groupBaseDN,omitempty"`

	// GroupFilter is the filter for groups
	GroupFilter string `json:"groupFilter,omitempty"`

	// GroupMemberAttribute is the attribute for group members
	GroupMemberAttribute string `json:"groupMemberAttribute,omitempty"`

	// UserAttributes are the attributes to retrieve for users
	UserAttributes map[string]string `json:"userAttributes,omitempty"`

	// StartTLS indicates whether to use StartTLS
	StartTLS bool `json:"startTLS,omitempty"`

	// InsecureSkipVerify indicates whether to skip TLS verification
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// CACert is the CA certificate for TLS
	CACert string `json:"caCert,omitempty"`
}

// OAuthAuthConfig defines the configuration for OAuth authentication
type OAuthAuthConfig struct {
	// ProviderType is the type of OAuth provider
	ProviderType string `json:"providerType"`

	// ClientID is the client ID
	ClientID string `json:"clientID"`

	// ClientSecret is the client secret
	ClientSecret string `json:"clientSecret"`

	// AuthorizationURL is the authorization URL
	AuthorizationURL string `json:"authorizationURL"`

	// TokenURL is the token URL
	TokenURL string `json:"tokenURL"`

	// UserInfoURL is the user info URL
	UserInfoURL string `json:"userInfoURL"`

	// RedirectURL is the redirect URL
	RedirectURL string `json:"redirectURL"`

	// Scopes are the scopes to request
	Scopes []string `json:"scopes,omitempty"`

	// UserIDAttribute is the attribute for user IDs
	UserIDAttribute string `json:"userIDAttribute,omitempty"`

	// UserAttributes are the attributes to retrieve for users
	UserAttributes map[string]string `json:"userAttributes,omitempty"`
}

// SAMLAuthConfig defines the configuration for SAML authentication
type SAMLAuthConfig struct {
	// MetadataURL is the URL of the SAML metadata
	MetadataURL string `json:"metadataURL"`

	// EntityID is the entity ID
	EntityID string `json:"entityID"`

	// AssertionConsumerServiceURL is the assertion consumer service URL
	AssertionConsumerServiceURL string `json:"assertionConsumerServiceURL"`

	// SignAuthnRequests indicates whether to sign authentication requests
	SignAuthnRequests bool `json:"signAuthnRequests,omitempty"`

	// SigningCert is the signing certificate
	SigningCert string `json:"signingCert,omitempty"`

	// SigningKey is the signing key
	SigningKey string `json:"signingKey,omitempty"`

	// EncryptionCert is the encryption certificate
	EncryptionCert string `json:"encryptionCert,omitempty"`

	// EncryptionKey is the encryption key
	EncryptionKey string `json:"encryptionKey,omitempty"`

	// UserIDAttribute is the attribute for user IDs
	UserIDAttribute string `json:"userIDAttribute,omitempty"`

	// UserAttributes are the attributes to retrieve for users
	UserAttributes map[string]string `json:"userAttributes,omitempty"`
}

// RADIUSAuthConfig defines the configuration for RADIUS authentication
type RADIUSAuthConfig struct {
	// Server is the RADIUS server
	Server string `json:"server"`

	// Port is the RADIUS port
	Port int `json:"port,omitempty"`

	// Secret is the RADIUS secret
	Secret string `json:"secret"`

	// Timeout is the timeout in seconds
	Timeout int `json:"timeout,omitempty"`

	// Retries is the number of retries
	Retries int `json:"retries,omitempty"`

	// NASIdentifier is the NAS identifier
	NASIdentifier string `json:"nasIdentifier,omitempty"`
}

// CertificateAuthConfig defines the configuration for certificate authentication
type CertificateAuthConfig struct {
	// CACert is the CA certificate
	CACert string `json:"caCert"`

	// UserCertAttribute is the attribute for user certificates
	UserCertAttribute string `json:"userCertAttribute,omitempty"`

	// UserIDAttribute is the attribute for user IDs
	UserIDAttribute string `json:"userIDAttribute,omitempty"`

	// VerifyClient indicates whether to verify the client
	VerifyClient bool `json:"verifyClient,omitempty"`
}

// AuthProviderStatus defines the observed state of an authentication provider
type AuthProviderStatus struct {
	// Phase is the current phase of the provider
	Phase string `json:"phase,omitempty"`

	// Conditions are the current conditions of the provider
	Conditions []AuthProviderCondition `json:"conditions,omitempty"`

	// UserCount is the number of users
	UserCount int `json:"userCount,omitempty"`

	// GroupCount is the number of groups
	GroupCount int `json:"groupCount,omitempty"`

	// LastSyncTime is the time of the last synchronization
	LastSyncTime metav1.Time `json:"lastSyncTime,omitempty"`
}

// AuthProviderCondition defines a condition of an authentication provider
type AuthProviderCondition struct {
	// Type is the type of the condition
	Type string `json:"type"`

	// Status is the status of the condition
	Status string `json:"status"`

	// Reason is the reason for the condition
	Reason string `json:"reason,omitempty"`

	// Message is the message for the condition
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the time of the last transition
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthProviderList contains a list of AuthProvider
type AuthProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthProvider `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthConfig defines the authentication configuration
type AuthConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthConfigSpec   `json:"spec"`
	Status AuthConfigStatus `json:"status,omitempty"`
}

// AuthConfigSpec defines the desired state of the authentication configuration
type AuthConfigSpec struct {
	// DefaultProvider is the default authentication provider
	DefaultProvider string `json:"defaultProvider"`

	// TokenExpiration is the token expiration time in seconds
	TokenExpiration int `json:"tokenExpiration,omitempty"`

	// RefreshTokenExpiration is the refresh token expiration time in seconds
	RefreshTokenExpiration int `json:"refreshTokenExpiration,omitempty"`

	// EnableAuditLogging indicates whether to enable audit logging
	EnableAuditLogging bool `json:"enableAuditLogging,omitempty"`

	// AuditLogPath is the path to the audit log file
	AuditLogPath string `json:"auditLogPath,omitempty"`

	// Resources are the resource requirements
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector is the node selector for deployment
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// AuthConfigStatus defines the observed state of the authentication configuration
type AuthConfigStatus struct {
	// Phase is the current phase of the configuration
	Phase string `json:"phase,omitempty"`

	// Conditions are the current conditions of the configuration
	Conditions []AuthConfigCondition `json:"conditions,omitempty"`

	// ProviderCount is the number of providers
	ProviderCount int `json:"providerCount,omitempty"`

	// UserCount is the number of users
	UserCount int `json:"userCount,omitempty"`

	// GroupCount is the number of groups
	GroupCount int `json:"groupCount,omitempty"`
}

// AuthConfigCondition defines a condition of the authentication configuration
type AuthConfigCondition struct {
	// Type is the type of the condition
	Type string `json:"type"`

	// Status is the status of the condition
	Status string `json:"status"`

	// Reason is the reason for the condition
	Reason string `json:"reason,omitempty"`

	// Message is the message for the condition
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the time of the last transition
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthConfigList contains a list of AuthConfig
type AuthConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthConfig `json:"items"`
}
