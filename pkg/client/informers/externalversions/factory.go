package externalversions

import (
	"reflect"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	networkv1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1"
	clientset "github.com/GizmoTickler/fos1/pkg/client/clientset/versioned"
	listersv1 "github.com/GizmoTickler/fos1/pkg/client/listers/network/v1"
)

// SharedInformerFactory provides shared informers for resources
type SharedInformerFactory interface {
	// Network returns the network informer group
	Network() NetworkInformers
}

// NetworkInformers provides access to network resource informers
type NetworkInformers interface {
	// V1 returns the v1 network informer group
	V1() NetworkV1Informers
}

// NetworkV1Informers provides access to v1 network resource informers
type NetworkV1Informers interface {
	// DHCPv4Services returns a DHCPv4ServiceInformer
	DHCPv4Services() DHCPv4ServiceInformer
	// DHCPv6Services returns a DHCPv6ServiceInformer
	DHCPv6Services() DHCPv6ServiceInformer
	// VLANs returns a VLANInformer
	VLANs() VLANInformer
}

// DHCPv4ServiceInformer provides access to a shared informer and lister for DHCPv4Services
type DHCPv4ServiceInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() listersv1.DHCPv4ServiceLister
}

// DHCPv6ServiceInformer provides access to a shared informer and lister for DHCPv6Services
type DHCPv6ServiceInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() listersv1.DHCPv6ServiceLister
}

// VLANInformer provides access to a shared informer and lister for VLANs
type VLANInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() listersv1.VLANLister
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
	client           clientset.Interface
	defaultResync    time.Duration
	informers        map[reflect.Type]cache.SharedIndexInformer
	startedInformers map[reflect.Type]bool
	lock             sync.Mutex
}

// Network returns the network informer group
func (f *sharedInformerFactory) Network() NetworkInformers {
	return &networkInformers{factory: f}
}

type networkInformers struct {
	factory *sharedInformerFactory
}

// V1 returns the v1 network informer group
func (n *networkInformers) V1() NetworkV1Informers {
	return &networkV1Informers{factory: n.factory}
}

type networkV1Informers struct {
	factory *sharedInformerFactory
}

func (v *networkV1Informers) DHCPv4Services() DHCPv4ServiceInformer {
	return &dhcpv4ServiceInformer{factory: v.factory}
}

func (v *networkV1Informers) DHCPv6Services() DHCPv6ServiceInformer {
	return &dhcpv6ServiceInformer{factory: v.factory}
}

func (v *networkV1Informers) VLANs() VLANInformer {
	return &vlanInformer{factory: v.factory}
}

// --- DHCPv4Service informer ---

type dhcpv4ServiceInformer struct {
	factory *sharedInformerFactory
}

func (i *dhcpv4ServiceInformer) Informer() cache.SharedIndexInformer {
	return i.factory.getInformer(reflect.TypeOf(&networkv1.DHCPv4Service{}))
}

func (i *dhcpv4ServiceInformer) Lister() listersv1.DHCPv4ServiceLister {
	return &dhcpv4ServiceLister{indexer: i.Informer().GetIndexer()}
}

type dhcpv4ServiceLister struct {
	indexer cache.Indexer
}

func (l *dhcpv4ServiceLister) List(selector labels.Selector) (ret []*networkv1.DHCPv4Service, err error) {
	return ret, nil
}

func (l *dhcpv4ServiceLister) DHCPv4Services(namespace string) listersv1.DHCPv4ServiceNamespaceLister {
	return &dhcpv4ServiceNamespaceLister{indexer: l.indexer, namespace: namespace}
}

type dhcpv4ServiceNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

func (l *dhcpv4ServiceNamespaceLister) List(selector labels.Selector) (ret []*networkv1.DHCPv4Service, err error) {
	return ret, nil
}

func (l *dhcpv4ServiceNamespaceLister) Get(name string) (*networkv1.DHCPv4Service, error) {
	return nil, nil
}

// --- DHCPv6Service informer ---

type dhcpv6ServiceInformer struct {
	factory *sharedInformerFactory
}

func (i *dhcpv6ServiceInformer) Informer() cache.SharedIndexInformer {
	return i.factory.getInformer(reflect.TypeOf(&networkv1.DHCPv6Service{}))
}

func (i *dhcpv6ServiceInformer) Lister() listersv1.DHCPv6ServiceLister {
	return &dhcpv6ServiceLister{indexer: i.Informer().GetIndexer()}
}

type dhcpv6ServiceLister struct {
	indexer cache.Indexer
}

func (l *dhcpv6ServiceLister) List(selector labels.Selector) (ret []*networkv1.DHCPv6Service, err error) {
	return ret, nil
}

func (l *dhcpv6ServiceLister) DHCPv6Services(namespace string) listersv1.DHCPv6ServiceNamespaceLister {
	return &dhcpv6ServiceNamespaceLister{indexer: l.indexer, namespace: namespace}
}

type dhcpv6ServiceNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

func (l *dhcpv6ServiceNamespaceLister) List(selector labels.Selector) (ret []*networkv1.DHCPv6Service, err error) {
	return ret, nil
}

func (l *dhcpv6ServiceNamespaceLister) Get(name string) (*networkv1.DHCPv6Service, error) {
	return nil, nil
}

// --- VLAN informer ---

type vlanInformer struct {
	factory *sharedInformerFactory
}

func (i *vlanInformer) Informer() cache.SharedIndexInformer {
	return i.factory.getInformer(reflect.TypeOf(&networkv1.VLAN{}))
}

func (i *vlanInformer) Lister() listersv1.VLANLister {
	return &vlanLister{indexer: i.Informer().GetIndexer()}
}

type vlanLister struct {
	indexer cache.Indexer
}

func (l *vlanLister) List(selector labels.Selector) (ret []*networkv1.VLAN, err error) {
	return ret, nil
}

func (l *vlanLister) VLANs(namespace string) listersv1.VLANNamespaceLister {
	return &vlanNamespaceLister{indexer: l.indexer, namespace: namespace}
}

type vlanNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

func (l *vlanNamespaceLister) List(selector labels.Selector) (ret []*networkv1.VLAN, err error) {
	return ret, nil
}

func (l *vlanNamespaceLister) Get(name string) (*networkv1.VLAN, error) {
	return nil, nil
}

// getInformer returns a shared informer for the given type, creating one if needed
func (f *sharedInformerFactory) getInformer(t reflect.Type) cache.SharedIndexInformer {
	f.lock.Lock()
	defer f.lock.Unlock()

	informer, exists := f.informers[t]
	if exists {
		return informer
	}

	// Create a placeholder informer
	informer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return nil, nil
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return nil, nil
			},
		},
		nil,
		f.defaultResync,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	f.informers[t] = informer

	return informer
}
