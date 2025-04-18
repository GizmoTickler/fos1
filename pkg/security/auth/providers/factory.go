package providers

import (
	"fmt"

	"github.com/varuntirumala1/fos1/pkg/security/auth"
)

// Factory creates authentication providers
type Factory struct {
	// Providers are the registered provider constructors
	providers map[string]ProviderConstructor
}

// ProviderConstructor is a function that creates a provider
type ProviderConstructor func(info *auth.ProviderInfo) (auth.Provider, error)

// NewFactory creates a new provider factory
func NewFactory() *Factory {
	factory := &Factory{
		providers: make(map[string]ProviderConstructor),
	}

	// Register default providers
	factory.RegisterProvider("local", NewLocalProviderFromInfo)
	factory.RegisterProvider("ldap", NewLDAPProviderFromInfo)
	factory.RegisterProvider("oauth", NewOAuthProviderFromInfo)

	return factory
}

// RegisterProvider registers a provider constructor
func (f *Factory) RegisterProvider(providerType string, constructor ProviderConstructor) {
	f.providers[providerType] = constructor
}

// CreateProvider creates a provider
func (f *Factory) CreateProvider(info *auth.ProviderInfo) (auth.Provider, error) {
	if info == nil {
		return nil, fmt.Errorf("provider info is nil")
	}

	if info.Type == "" {
		return nil, fmt.Errorf("provider type is required")
	}

	constructor, exists := f.providers[info.Type]
	if !exists {
		return nil, fmt.Errorf("unsupported provider type: %s", info.Type)
	}

	return constructor(info)
}

// NewLocalProviderFromInfo creates a local provider from provider info
func NewLocalProviderFromInfo(info *auth.ProviderInfo) (auth.Provider, error) {
	if info == nil {
		return nil, fmt.Errorf("provider info is nil")
	}

	if info.Config.Local == nil {
		return nil, fmt.Errorf("local provider configuration is nil")
	}

	config := &LocalConfig{
		Name:                  info.Name,
		Enabled:               info.Enabled,
		Priority:              info.Priority,
		PasswordPolicy:        info.Config.Local.PasswordPolicy,
		MFAEnabled:            info.Config.Local.MFAEnabled,
		MFAMethods:            info.Config.Local.MFAMethods,
		TokenExpiration:       24 * 60 * 60 * time.Second,
		RefreshTokenExpiration: 7 * 24 * 60 * 60 * time.Second,
	}

	return NewLocalProvider(config)
}

// NewLDAPProviderFromInfo creates an LDAP provider from provider info
func NewLDAPProviderFromInfo(info *auth.ProviderInfo) (auth.Provider, error) {
	if info == nil {
		return nil, fmt.Errorf("provider info is nil")
	}

	if info.Config.LDAP == nil {
		return nil, fmt.Errorf("LDAP provider configuration is nil")
	}

	config := &LDAPConfig{
		Name:                 info.Name,
		Enabled:              info.Enabled,
		Priority:             info.Priority,
		URL:                  info.Config.LDAP.URL,
		BindDN:               info.Config.LDAP.BindDN,
		BindPassword:         info.Config.LDAP.BindPassword,
		UserBaseDN:           info.Config.LDAP.UserBaseDN,
		UserFilter:           info.Config.LDAP.UserFilter,
		GroupBaseDN:          info.Config.LDAP.GroupBaseDN,
		GroupFilter:          info.Config.LDAP.GroupFilter,
		GroupMemberAttribute: info.Config.LDAP.GroupMemberAttribute,
		UserAttributes:       info.Config.LDAP.UserAttributes,
		StartTLS:             info.Config.LDAP.StartTLS,
		InsecureSkipVerify:   info.Config.LDAP.InsecureSkipVerify,
		CACert:               info.Config.LDAP.CACert,
		TokenExpiration:      24 * 60 * 60 * time.Second,
		RefreshTokenExpiration: 7 * 24 * 60 * 60 * time.Second,
	}

	return NewLDAPProvider(config)
}

// NewOAuthProviderFromInfo creates an OAuth provider from provider info
func NewOAuthProviderFromInfo(info *auth.ProviderInfo) (auth.Provider, error) {
	if info == nil {
		return nil, fmt.Errorf("provider info is nil")
	}

	if info.Config.OAuth == nil {
		return nil, fmt.Errorf("OAuth provider configuration is nil")
	}

	config := &OAuthConfig{
		Name:                info.Name,
		Enabled:             info.Enabled,
		Priority:            info.Priority,
		ProviderType:        info.Config.OAuth.ProviderType,
		ClientID:            info.Config.OAuth.ClientID,
		ClientSecret:        info.Config.OAuth.ClientSecret,
		AuthorizationURL:    info.Config.OAuth.AuthorizationURL,
		TokenURL:            info.Config.OAuth.TokenURL,
		UserInfoURL:         info.Config.OAuth.UserInfoURL,
		RedirectURL:         info.Config.OAuth.RedirectURL,
		Scopes:              info.Config.OAuth.Scopes,
		UserIDAttribute:     info.Config.OAuth.UserIDAttribute,
		UserAttributes:      info.Config.OAuth.UserAttributes,
		TokenExpiration:     24 * 60 * 60 * time.Second,
		RefreshTokenExpiration: 7 * 24 * 60 * 60 * time.Second,
	}

	return NewOAuthProvider(config)
}
