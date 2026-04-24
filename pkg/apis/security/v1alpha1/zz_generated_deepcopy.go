package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// --- SuricataInstance ---

// DeepCopyObject implements runtime.Object.
func (in *SuricataInstance) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of SuricataInstance.
func (in *SuricataInstance) DeepCopy() *SuricataInstance {
	if in == nil {
		return nil
	}
	out := new(SuricataInstance)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another SuricataInstance.
func (in *SuricataInstance) DeepCopyInto(out *SuricataInstance) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- SuricataInstanceList ---

// DeepCopyObject implements runtime.Object.
func (in *SuricataInstanceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of SuricataInstanceList.
func (in *SuricataInstanceList) DeepCopy() *SuricataInstanceList {
	if in == nil {
		return nil
	}
	out := new(SuricataInstanceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another SuricataInstanceList.
func (in *SuricataInstanceList) DeepCopyInto(out *SuricataInstanceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SuricataInstance, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// --- ZeekInstance ---

// DeepCopyObject implements runtime.Object.
func (in *ZeekInstance) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of ZeekInstance.
func (in *ZeekInstance) DeepCopy() *ZeekInstance {
	if in == nil {
		return nil
	}
	out := new(ZeekInstance)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another ZeekInstance.
func (in *ZeekInstance) DeepCopyInto(out *ZeekInstance) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- ZeekInstanceList ---

// DeepCopyObject implements runtime.Object.
func (in *ZeekInstanceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of ZeekInstanceList.
func (in *ZeekInstanceList) DeepCopy() *ZeekInstanceList {
	if in == nil {
		return nil
	}
	out := new(ZeekInstanceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another ZeekInstanceList.
func (in *ZeekInstanceList) DeepCopyInto(out *ZeekInstanceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ZeekInstance, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// --- EventCorrelation ---

// DeepCopyObject implements runtime.Object.
func (in *EventCorrelation) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of EventCorrelation.
func (in *EventCorrelation) DeepCopy() *EventCorrelation {
	if in == nil {
		return nil
	}
	out := new(EventCorrelation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another EventCorrelation.
func (in *EventCorrelation) DeepCopyInto(out *EventCorrelation) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- EventCorrelationList ---

// DeepCopyObject implements runtime.Object.
func (in *EventCorrelationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of EventCorrelationList.
func (in *EventCorrelationList) DeepCopy() *EventCorrelationList {
	if in == nil {
		return nil
	}
	out := new(EventCorrelationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another EventCorrelationList.
func (in *EventCorrelationList) DeepCopyInto(out *EventCorrelationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]EventCorrelation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// --- AuthProvider ---

// DeepCopyObject implements runtime.Object.
func (in *AuthProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of AuthProvider.
func (in *AuthProvider) DeepCopy() *AuthProvider {
	if in == nil {
		return nil
	}
	out := new(AuthProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another AuthProvider.
func (in *AuthProvider) DeepCopyInto(out *AuthProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- AuthProviderList ---

// DeepCopyObject implements runtime.Object.
func (in *AuthProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of AuthProviderList.
func (in *AuthProviderList) DeepCopy() *AuthProviderList {
	if in == nil {
		return nil
	}
	out := new(AuthProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another AuthProviderList.
func (in *AuthProviderList) DeepCopyInto(out *AuthProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AuthProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// --- AuthConfig ---

// DeepCopyObject implements runtime.Object.
func (in *AuthConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of AuthConfig.
func (in *AuthConfig) DeepCopy() *AuthConfig {
	if in == nil {
		return nil
	}
	out := new(AuthConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another AuthConfig.
func (in *AuthConfig) DeepCopyInto(out *AuthConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// --- AuthConfigList ---

// DeepCopyObject implements runtime.Object.
func (in *AuthConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of AuthConfigList.
func (in *AuthConfigList) DeepCopy() *AuthConfigList {
	if in == nil {
		return nil
	}
	out := new(AuthConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another AuthConfigList.
func (in *AuthConfigList) DeepCopyInto(out *AuthConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AuthConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// --- ThreatFeed ---

// DeepCopyObject implements runtime.Object.
func (in *ThreatFeed) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of ThreatFeed.
func (in *ThreatFeed) DeepCopy() *ThreatFeed {
	if in == nil {
		return nil
	}
	out := new(ThreatFeed)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another ThreatFeed.
func (in *ThreatFeed) DeepCopyInto(out *ThreatFeed) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopyInto copies all properties into another ThreatFeedSpec. Required
// once AuthSecretRef became a pointer (Sprint 31 / Ticket 53).
func (in *ThreatFeedSpec) DeepCopyInto(out *ThreatFeedSpec) {
	*out = *in
	if in.AuthSecretRef != nil {
		cp := *in.AuthSecretRef
		out.AuthSecretRef = &cp
	}
}

// DeepCopy creates a deep copy of ThreatFeedStatus.
func (in *ThreatFeedStatus) DeepCopy() *ThreatFeedStatus {
	if in == nil {
		return nil
	}
	out := new(ThreatFeedStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another ThreatFeedStatus.
func (in *ThreatFeedStatus) DeepCopyInto(out *ThreatFeedStatus) {
	*out = *in
	in.LastFetchTime.DeepCopyInto(&out.LastFetchTime)
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]ThreatFeedCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopyInto copies all properties into another ThreatFeedCondition.
func (in *ThreatFeedCondition) DeepCopyInto(out *ThreatFeedCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

// --- ThreatFeedList ---

// DeepCopyObject implements runtime.Object.
func (in *ThreatFeedList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of ThreatFeedList.
func (in *ThreatFeedList) DeepCopy() *ThreatFeedList {
	if in == nil {
		return nil
	}
	out := new(ThreatFeedList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another ThreatFeedList.
func (in *ThreatFeedList) DeepCopyInto(out *ThreatFeedList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ThreatFeed, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}
