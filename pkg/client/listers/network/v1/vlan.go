package v1

import (
	"k8s.io/apimachinery/pkg/labels"

	networkv1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1"
)

// VLANLister helps list VLANs
type VLANLister interface {
	// List lists all VLANs in the indexer
	List(selector labels.Selector) (ret []*networkv1.VLAN, err error)
	// VLANs returns an object that can list and get VLANs
	VLANs(namespace string) VLANNamespaceLister
}

// VLANNamespaceLister helps list and get VLANs
type VLANNamespaceLister interface {
	// List lists all VLANs in the indexer for a given namespace
	List(selector labels.Selector) (ret []*networkv1.VLAN, err error)
	// Get retrieves the VLAN from the indexer for a given namespace and name
	Get(name string) (*networkv1.VLAN, error)
}
