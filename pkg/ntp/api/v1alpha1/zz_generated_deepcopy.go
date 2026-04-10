package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyObject implements runtime.Object for NTPService.
func (in *NTPService) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(NTPService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all fields into another NTPService.
func (in *NTPService) DeepCopyInto(out *NTPService) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopyInto copies NTPServiceSpec fields.
func (in *NTPServiceSpec) DeepCopyInto(out *NTPServiceSpec) {
	*out = *in
	in.Sources.DeepCopyInto(&out.Sources)
	out.Server = in.Server
	in.Security.DeepCopyInto(&out.Security)
	if in.VLANConfig != nil {
		out.VLANConfig = make([]VLANConfig, len(in.VLANConfig))
		copy(out.VLANConfig, in.VLANConfig)
	}
	out.Monitoring = in.Monitoring
}

// DeepCopyInto copies Sources fields.
func (in *Sources) DeepCopyInto(out *Sources) {
	*out = *in
	if in.Pools != nil {
		out.Pools = make([]PoolSource, len(in.Pools))
		copy(out.Pools, in.Pools)
	}
	if in.Servers != nil {
		out.Servers = make([]ServerSource, len(in.Servers))
		copy(out.Servers, in.Servers)
	}
	out.Hardware = in.Hardware
}

// DeepCopyInto copies SecurityConfig fields.
func (in *SecurityConfig) DeepCopyInto(out *SecurityConfig) {
	*out = *in
	out.NTS = in.NTS
	in.Authentication.DeepCopyInto(&out.Authentication)
	out.RateLimit = in.RateLimit
	if in.Access != nil {
		out.Access = make([]AccessRule, len(in.Access))
		copy(out.Access, in.Access)
	}
}

// DeepCopyInto copies AuthConfig fields.
func (in *AuthConfig) DeepCopyInto(out *AuthConfig) {
	*out = *in
	if in.Keys != nil {
		out.Keys = make([]AuthKey, len(in.Keys))
		copy(out.Keys, in.Keys)
	}
}

// DeepCopyInto copies NTPServiceStatus fields.
func (in *NTPServiceStatus) DeepCopyInto(out *NTPServiceStatus) {
	*out = *in
	if in.Sources != nil {
		out.Sources = make([]SourceStatus, len(in.Sources))
		copy(out.Sources, in.Sources)
	}
}

// DeepCopyObject implements runtime.Object for NTPServiceList.
func (in *NTPServiceList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(NTPServiceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all fields into another NTPServiceList.
func (in *NTPServiceList) DeepCopyInto(out *NTPServiceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]NTPService, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
