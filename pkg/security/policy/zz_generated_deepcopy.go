package policy

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// --- FilterPolicy ---

// DeepCopyObject implements runtime.Object.
func (in *FilterPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of FilterPolicy.
func (in *FilterPolicy) DeepCopy() *FilterPolicy {
	if in == nil {
		return nil
	}
	out := new(FilterPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another FilterPolicy.
func (in *FilterPolicy) DeepCopyInto(out *FilterPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- FilterPolicyGroup ---

// DeepCopyObject implements runtime.Object.
func (in *FilterPolicyGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of FilterPolicyGroup.
func (in *FilterPolicyGroup) DeepCopy() *FilterPolicyGroup {
	if in == nil {
		return nil
	}
	out := new(FilterPolicyGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another FilterPolicyGroup.
func (in *FilterPolicyGroup) DeepCopyInto(out *FilterPolicyGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- FilterZone ---

// DeepCopyObject implements runtime.Object.
func (in *FilterZone) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of FilterZone.
func (in *FilterZone) DeepCopy() *FilterZone {
	if in == nil {
		return nil
	}
	out := new(FilterZone)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another FilterZone.
func (in *FilterZone) DeepCopyInto(out *FilterZone) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- FilterPolicyTemplate ---

// DeepCopyObject implements runtime.Object.
func (in *FilterPolicyTemplate) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of FilterPolicyTemplate.
func (in *FilterPolicyTemplate) DeepCopy() *FilterPolicyTemplate {
	if in == nil {
		return nil
	}
	out := new(FilterPolicyTemplate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another FilterPolicyTemplate.
func (in *FilterPolicyTemplate) DeepCopyInto(out *FilterPolicyTemplate) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}
