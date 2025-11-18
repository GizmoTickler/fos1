package v1

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	networkv1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1"
)

// NetworkInterfaceLister helps list NetworkInterfaces
type NetworkInterfaceLister interface {
	// List lists all NetworkInterfaces in the indexer
	List(selector labels.Selector) (ret []*networkv1.NetworkInterface, err error)
	// NetworkInterfaces returns an object that can list and get NetworkInterfaces
	NetworkInterfaces(namespace string) NetworkInterfaceNamespaceLister
}

// NetworkInterfaceNamespaceLister helps list and get NetworkInterfaces
type NetworkInterfaceNamespaceLister interface {
	// List lists all NetworkInterfaces in the indexer for a given namespace
	List(selector labels.Selector) (ret []*networkv1.NetworkInterface, err error)
	// Get retrieves the NetworkInterface from the indexer for a given namespace and name
	Get(name string) (*networkv1.NetworkInterface, error)
}
