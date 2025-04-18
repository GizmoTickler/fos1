package versioned

import (
	"k8s.io/client-go/rest"
)

// Interface defines the methods a versioned clientset must implement
type Interface interface {
	// Add methods as needed
}

// Clientset contains the clients for groups
type Clientset struct {
	// Add clients as needed
}

// NewForConfig creates a new Clientset for the given config
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c

	// Create a new clientset
	cs := &Clientset{}

	return cs, nil
}
