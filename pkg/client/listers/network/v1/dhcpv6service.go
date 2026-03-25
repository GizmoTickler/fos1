package v1

import (
	"k8s.io/apimachinery/pkg/labels"

	networkv1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1"
)

// DHCPv6ServiceLister helps list DHCPv6Services
type DHCPv6ServiceLister interface {
	// List lists all DHCPv6Services in the indexer
	List(selector labels.Selector) (ret []*networkv1.DHCPv6Service, err error)
	// DHCPv6Services returns an object that can list and get DHCPv6Services
	DHCPv6Services(namespace string) DHCPv6ServiceNamespaceLister
}

// DHCPv6ServiceNamespaceLister helps list and get DHCPv6Services
type DHCPv6ServiceNamespaceLister interface {
	// List lists all DHCPv6Services in the indexer for a given namespace
	List(selector labels.Selector) (ret []*networkv1.DHCPv6Service, err error)
	// Get retrieves the DHCPv6Service from the indexer for a given namespace and name
	Get(name string) (*networkv1.DHCPv6Service, error)
}
