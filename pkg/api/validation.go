package api

import (
	"fmt"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// supportedPolicyActions enumerates the Spec.Actions[i].Type tokens the
// translator at pkg/security/policy/translator.go:translatePolicyAction
// understands. Validation rejects anything else with a structured 422 so
// clients cannot silently ship a spec that translates to the default deny
// verdict (which would be confusing for an operator who typed "permit"
// expecting an allow).
var supportedPolicyActions = map[string]struct{}{
	"allow":  {},
	"accept": {},
	"deny":   {},
	"drop":   {},
	"reject": {},
	// "log" is accepted as a non-terminal action — it does not change the
	// verdict but is a valid action type per the translator.
	"log": {},
}

// supportedPolicyScopes enumerates the FilterPolicy.Spec.Scope tokens the
// controller recognises. The set is intentionally permissive — the scope
// string is free-form metadata in the CRD — but we at least reject empty
// scope to catch common authoring mistakes. Keep in sync with the example
// manifests under manifests/examples/security/.
var supportedPolicyScopes = map[string]struct{}{
	"zone":      {},
	"namespace": {},
	"cluster":   {},
	"interface": {},
	"global":    {},
}

// supportedPortProtocols enumerates the protocol tokens the translator
// understands (see translateCiliumProtocol at translator.go:137). Other
// protocols are still accepted with a warning — the translator treats them
// as "any" — so validation rejects only obviously-malformed values here.
var supportedPortProtocols = map[string]struct{}{
	"tcp":  {},
	"udp":  {},
	"icmp": {},
	"any":  {},
	"":     {}, // explicit empty protocol == any
}

// ValidateFilterPolicy returns a field.ErrorList describing every problem
// in fp's Spec (and its metadata when it carries write-path requirements).
// An empty list means the object is acceptable. The function is shared by
// the REST API handlers and any future admission webhook — keep it pure
// (no Kubernetes client calls, no environmental lookups).
//
// The validator is intentionally conservative: it rejects inputs that are
// unambiguously malformed, but tolerates author choices the translator
// handles at runtime (for example unknown selector types are downgraded to
// a no-match, which is not a failure mode worth a 422).
func ValidateFilterPolicy(fp *policy.FilterPolicy) field.ErrorList {
	var errs field.ErrorList
	if fp == nil {
		return append(errs, field.Required(field.NewPath(""), "filterpolicy object must not be nil"))
	}

	errs = append(errs, validateObjectMeta(&fp.ObjectMeta, field.NewPath("metadata"))...)
	errs = append(errs, validateFilterPolicySpec(&fp.Spec, field.NewPath("spec"))...)
	return errs
}

// validateObjectMeta enforces the pieces of ObjectMeta the REST API cares
// about on write. We require a name (apiserver also requires this, but we
// prefer returning the error before the Kubernetes round-trip) and refuse
// an explicit generateName because the v0 API does not support POST-with-
// GenerateName (the URL shape pins the name).
func validateObjectMeta(meta *metav1.ObjectMeta, fp *field.Path) field.ErrorList {
	var errs field.ErrorList
	if meta == nil {
		return append(errs, field.Required(fp, "metadata is required"))
	}
	if strings.TrimSpace(meta.Name) == "" {
		errs = append(errs, field.Required(fp.Child("name"), "name is required"))
	}
	if strings.TrimSpace(meta.GenerateName) != "" {
		errs = append(errs, field.Forbidden(fp.Child("generateName"),
			"generateName is not supported by the v1 write-path API; POST with an explicit name"))
	}
	return errs
}

// validateFilterPolicySpec validates the Spec block. Rules:
//
//   - Scope is required and must be one of supportedPolicyScopes.
//   - Priority must be non-negative; the controller treats negative
//     priorities as invalid because it uses unsigned comparison when
//     sorting translated Cilium rules.
//   - Actions slice must be non-empty and every element must carry a
//     recognised Type.
//   - Selectors: at least one of sources/destinations/applications/ports
//     must be populated — a selector-empty FilterPolicy would apply to
//     every flow, which is almost always an authoring mistake. Operators
//     who really want match-all should use Scope=global with an empty
//     Sources + Destinations pair.
//   - Every PortSelector.Protocol must parse and every port must lie in
//     the TCP/UDP range (1..65535). Port zero is reserved and SCTP is not
//     yet plumbed through the translator.
func validateFilterPolicySpec(spec *policy.FilterPolicySpec, fp *field.Path) field.ErrorList {
	var errs field.ErrorList

	scope := strings.TrimSpace(strings.ToLower(spec.Scope))
	if scope == "" {
		errs = append(errs, field.Required(fp.Child("scope"), "scope is required"))
	} else if _, ok := supportedPolicyScopes[scope]; !ok {
		errs = append(errs, field.NotSupported(fp.Child("scope"), spec.Scope, sortedKeys(supportedPolicyScopes)))
	}

	if spec.Priority < 0 {
		errs = append(errs, field.Invalid(fp.Child("priority"), spec.Priority,
			"priority must be non-negative"))
	}

	errs = append(errs, validateActions(spec.Actions, fp.Child("actions"))...)
	errs = append(errs, validateSelectors(&spec.Selectors, fp.Child("selectors"))...)

	return errs
}

// validateActions checks that at least one PolicyAction is present and that
// every element uses a recognised Type token. The translator's default-deny
// behaviour means a typo would silently become "deny" — an annoying
// foot-gun — so we reject unknown types at the edge.
func validateActions(actions []policy.PolicyAction, fp *field.Path) field.ErrorList {
	var errs field.ErrorList
	if len(actions) == 0 {
		errs = append(errs, field.Required(fp, "at least one action is required"))
		return errs
	}
	for i, a := range actions {
		at := strings.TrimSpace(strings.ToLower(a.Type))
		if at == "" {
			errs = append(errs, field.Required(fp.Index(i).Child("type"), "action type is required"))
			continue
		}
		if _, ok := supportedPolicyActions[at]; !ok {
			errs = append(errs, field.NotSupported(fp.Index(i).Child("type"), a.Type, sortedKeys(supportedPolicyActions)))
		}
	}
	return errs
}

// validateSelectors rejects the empty-selectors case and validates any
// PortSelector entries. Sources / Destinations / Applications selectors
// are free-form per the CRD contract — the translator consumes what it
// understands and ignores the rest — so we do not enforce a fixed schema
// on them here.
func validateSelectors(sel *policy.FilterSelectors, fp *field.Path) field.ErrorList {
	var errs field.ErrorList
	if sel == nil {
		errs = append(errs, field.Required(fp, "selectors block is required"))
		return errs
	}

	if len(sel.Sources) == 0 && len(sel.Destinations) == 0 &&
		len(sel.Applications) == 0 && len(sel.Ports) == 0 {
		errs = append(errs, field.Required(fp, "at least one of sources/destinations/applications/ports must be set"))
	}

	for i, p := range sel.Ports {
		protoPath := fp.Child("ports").Index(i).Child("protocol")
		portsPath := fp.Child("ports").Index(i).Child("ports")
		proto := strings.TrimSpace(strings.ToLower(p.Protocol))
		if _, ok := supportedPortProtocols[proto]; !ok {
			errs = append(errs, field.NotSupported(protoPath, p.Protocol, sortedKeys(supportedPortProtocols)))
		}
		seen := make(map[int32]struct{}, len(p.Ports))
		for j, port := range p.Ports {
			portPath := portsPath.Index(j)
			if port < 1 || port > 65535 {
				errs = append(errs, field.Invalid(portPath, port, "port must be in the range 1..65535"))
			}
			if _, dup := seen[port]; dup {
				errs = append(errs, field.Duplicate(portPath, port))
			}
			seen[port] = struct{}{}
		}
	}
	return errs
}

// validationErrorsToStatus converts a field.ErrorList into the Kubernetes
// Status envelope served as a 422 body. The shape matches the envelope
// produced by kube-apiserver for `reason: Invalid`, which lets clients use
// a single decode path across our API surface and the upstream one.
func validationErrorsToStatus(errs field.ErrorList) map[string]any {
	causes := make([]map[string]any, 0, len(errs))
	messages := make([]string, 0, len(errs))
	for _, e := range errs {
		causes = append(causes, map[string]any{
			"reason":  string(e.Type),
			"message": e.ErrorBody(),
			"field":   e.Field,
		})
		messages = append(messages, e.Error())
	}
	return map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusUnprocessableEntity,
		"reason":  "Invalid",
		"message": fmt.Sprintf("FilterPolicy spec is invalid: %s", strings.Join(messages, "; ")),
		"details": map[string]any{
			"group":  policy.GroupVersion.Group,
			"kind":   "FilterPolicy",
			"causes": causes,
		},
	}
}

// sortedKeys returns the keys of m in lexical order. Used so
// field.NotSupported's "supported values" list is stable across runs.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Deterministic order matters for tests and OpenAPI documentation; we
	// sort ascending because that is what field.NotSupported expects.
	sortStrings(out)
	return out
}

// sortStrings is a tiny wrapper around the stdlib sort so this file has
// zero additional imports beyond the standard library + apimachinery. A
// direct sort.Strings call would work just as well but would force every
// caller of sortedKeys to pay for the sort package in their binary.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
