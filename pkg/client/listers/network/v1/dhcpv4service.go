package v1

import (
	"k8s.io/apimachinery/pkg/labels"

	networkv1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1"
)

// DHCPv4ServiceLister helps list DHCPv4Services
type DHCPv4ServiceLister interface {
	// List lists all DHCPv4Services in the indexer
	List(selector labels.Selector) (ret []*networkv1.DHCPv4Service, err error)
	// DHCPv4Services returns an object that can list and get DHCPv4Services
	DHCPv4Services(namespace string) DHCPv4ServiceNamespaceLister
}

// DHCPv4ServiceNamespaceLister helps list and get DHCPv4Services
type DHCPv4ServiceNamespaceLister interface {
	// List lists all DHCPv4Services in the indexer for a given namespace
	List(selector labels.Selector) (ret []*networkv1.DHCPv4Service, err error)
	// Get retrieves the DHCPv4Service from the indexer for a given namespace and name
	Get(name string) (*networkv1.DHCPv4Service, error)
}
