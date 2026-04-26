package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// --- TrafficShaper ---

// DeepCopyObject implements runtime.Object.
func (in *TrafficShaper) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of TrafficShaper.
func (in *TrafficShaper) DeepCopy() *TrafficShaper {
	if in == nil {
		return nil
	}
	out := new(TrafficShaper)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another TrafficShaper.
func (in *TrafficShaper) DeepCopyInto(out *TrafficShaper) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopyInto copies all properties into another TrafficShaperSpec. The
// Rules slice carries no nested pointers so a per-element value copy
// suffices, but we still take a fresh slice so mutations on the copy do
// not leak into the source.
func (in *TrafficShaperSpec) DeepCopyInto(out *TrafficShaperSpec) {
	*out = *in
	if in.Rules != nil {
		out.Rules = make([]TrafficShaperRule, len(in.Rules))
		copy(out.Rules, in.Rules)
	}
}

// DeepCopy creates a deep copy of TrafficShaperSpec.
func (in *TrafficShaperSpec) DeepCopy() *TrafficShaperSpec {
	if in == nil {
		return nil
	}
	out := new(TrafficShaperSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopy creates a deep copy of TrafficShaperStatus.
func (in *TrafficShaperStatus) DeepCopy() *TrafficShaperStatus {
	if in == nil {
		return nil
	}
	out := new(TrafficShaperStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another TrafficShaperStatus.
func (in *TrafficShaperStatus) DeepCopyInto(out *TrafficShaperStatus) {
	*out = *in
	in.LastUpdated.DeepCopyInto(&out.LastUpdated)
	if in.Conditions != nil {
		out.Conditions = make([]TrafficShaperCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyInto copies all properties into another TrafficShaperCondition.
func (in *TrafficShaperCondition) DeepCopyInto(out *TrafficShaperCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

// --- TrafficShaperList ---

// DeepCopyObject implements runtime.Object.
func (in *TrafficShaperList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of TrafficShaperList.
func (in *TrafficShaperList) DeepCopy() *TrafficShaperList {
	if in == nil {
		return nil
	}
	out := new(TrafficShaperList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another TrafficShaperList.
func (in *TrafficShaperList) DeepCopyInto(out *TrafficShaperList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]TrafficShaper, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
