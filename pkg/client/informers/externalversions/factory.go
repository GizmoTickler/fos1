package externalversions

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	clientset "github.com/GizmoTickler/fos1/pkg/client/clientset/versioned"
)

// SharedInformerFactory provides shared informers for resources
type SharedInformerFactory interface {
	// Add methods as needed
}

// NewSharedInformerFactory constructs a new instance of SharedInformerFactory
func NewSharedInformerFactory(client clientset.Interface, defaultResync time.Duration) SharedInformerFactory {
	return &sharedInformerFactory{
		client:           client,
		defaultResync:    defaultResync,
		informers:        make(map[reflect.Type]cache.SharedIndexInformer),
		startedInformers: make(map[reflect.Type]bool),
	}
}

type sharedInformerFactory struct {
	client        clientset.Interface
	defaultResync time.Duration
	informers     map[reflect.Type]cache.SharedIndexInformer
	startedInformers map[reflect.Type]bool
	lock          sync.Mutex
}
