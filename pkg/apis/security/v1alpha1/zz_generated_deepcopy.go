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
