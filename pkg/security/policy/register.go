// Package policy register.go provides Kubernetes scheme registration for
// FilterPolicy and related types so the controller-runtime client used by the
// REST management API (cmd/api-server) can serialize them as runtime.Objects.
package policy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the API group for FilterPolicy and related security CRDs.
// It matches the CRD manifest at manifests/base/security/filter-policy-crds.yaml
// (`apiVersion: security.fos1.io/v1alpha1`).
const GroupName = "security.fos1.io"

// GroupVersion is the group/version used to register the types in this
// package with a runtime scheme.
var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// SchemeBuilder collects the functions that add this package's types to a
// runtime.Scheme. Callers (e.g. cmd/api-server) use AddToScheme below.
var (
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types managed by this package to a runtime.Scheme.
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	localSchemeBuilder.Register(addKnownTypes)
}

// FilterPolicyList is a list of FilterPolicy resources. It is required by the
// Kubernetes client and cache machinery to List() FilterPolicy objects.
type FilterPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []FilterPolicy `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *FilterPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of FilterPolicyList.
func (in *FilterPolicyList) DeepCopy() *FilterPolicyList {
	if in == nil {
		return nil
	}
	out := new(FilterPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another FilterPolicyList.
func (in *FilterPolicyList) DeepCopyInto(out *FilterPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		items := make([]FilterPolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&items[i])
		}
		out.Items = items
	}
}

// addKnownTypes registers the FilterPolicy and FilterPolicyList types with
// the supplied scheme under GroupVersion. The REST API binary calls this via
// AddToScheme during controller-runtime manager construction.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&FilterPolicy{},
		&FilterPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
