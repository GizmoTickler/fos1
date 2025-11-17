package api

import (
	"github.com/GizmoTickler/fos1/pkg/ntp"
	"github.com/GizmoTickler/fos1/pkg/ntp/api/v1alpha1"
)

// ConvertToInternal converts from the CRD types to internal types
func ConvertToInternal(crd *v1alpha1.NTPService) *ntp.NTPService {
	if crd == nil {
		return nil
	}

	return &ntp.NTPService{
		Name:       crd.Name,
		Enabled:    crd.Spec.Enabled,
		Sources:    convertSources(&crd.Spec.Sources),
		Server:     convertServer(&crd.Spec.Server),
		Security:   convertSecurity(&crd.Spec.Security),
		VLANConfig: convertVLANConfig(crd.Spec.VLANConfig),
		Monitoring: convertMonitoring(&crd.Spec.Monitoring),
	}
}

// convertSources converts from CRD sources to internal sources
func convertSources(src *v1alpha1.Sources) ntp.Sources {
	if src == nil {
		return ntp.Sources{}
	}

	pools := make([]ntp.PoolSource, 0, len(src.Pools))
	for _, pool := range src.Pools {
		pools = append(pools, ntp.PoolSource{
			Name:    pool.Name,
			Servers: pool.Servers,
			IBurst:  pool.IBurst,
			Prefer:  pool.Prefer,
		})
	}

	servers := make([]ntp.ServerSource, 0, len(src.Servers))
	for _, server := range src.Servers {
		servers = append(servers, ntp.ServerSource{
			Address: server.Address,
			IBurst:  server.IBurst,
			Prefer:  server.Prefer,
			MinPoll: server.MinPoll,
			MaxPoll: server.MaxPoll,
		})
	}

	return ntp.Sources{
		Pools:   pools,
		Servers: servers,
		Hardware: ntp.HardwareSources{
			PPS: ntp.PPSSource{
				Enabled: src.Hardware.PPS.Enabled,
				Device:  src.Hardware.PPS.Device,
				Prefer:  src.Hardware.PPS.Prefer,
			},
			GPS: ntp.GPSSource{
				Enabled:  src.Hardware.GPS.Enabled,
				Device:   src.Hardware.GPS.Device,
				RefClock: src.Hardware.GPS.RefClock,
				Prefer:   src.Hardware.GPS.Prefer,
			},
		},
	}
}

// convertServer converts from CRD server config to internal server config
func convertServer(src *v1alpha1.ServerConfig) ntp.ServerConfig {
	if src == nil {
		return ntp.ServerConfig{}
	}

	return ntp.ServerConfig{
		Stratum:   src.Stratum,
		DriftFile: src.DriftFile,
		MakeStep: ntp.StepConfig{
			Threshold: src.MakeStep.Threshold,
			Limit:     src.MakeStep.Limit,
		},
		Local: ntp.LocalClockConfig{
			Enabled: src.Local.Enabled,
			Stratum: src.Local.Stratum,
		},
	}
}

// convertSecurity converts from CRD security config to internal security config
func convertSecurity(src *v1alpha1.SecurityConfig) ntp.SecurityConfig {
	if src == nil {
		return ntp.SecurityConfig{}
	}

	keys := make([]ntp.AuthKey, 0, len(src.Authentication.Keys))
	for _, key := range src.Authentication.Keys {
		keys = append(keys, ntp.AuthKey{
			ID:    key.ID,
			Type:  key.Type,
			Value: key.Value,
		})
	}

	access := make([]ntp.AccessRule, 0, len(src.Access))
	for _, rule := range src.Access {
		access = append(access, ntp.AccessRule{
			Network:    rule.Network,
			Permission: rule.Permission,
		})
	}

	return ntp.SecurityConfig{
		NTS: ntp.NTSConfig{
			Enabled: src.NTS.Enabled,
		},
		Authentication: ntp.AuthConfig{
			Enabled: src.Authentication.Enabled,
			Keys:    keys,
		},
		RateLimit: ntp.RateLimitConfig{
			Enabled:  src.RateLimit.Enabled,
			Interval: src.RateLimit.Interval,
			Burst:    src.RateLimit.Burst,
		},
		Access: access,
	}
}

// convertVLANConfig converts from CRD VLAN config to internal VLAN config
func convertVLANConfig(src []v1alpha1.VLANConfig) []ntp.VLANConfig {
	if src == nil {
		return nil
	}

	result := make([]ntp.VLANConfig, 0, len(src))
	for _, vlan := range src {
		result = append(result, ntp.VLANConfig{
			VLANRef:     vlan.VLANRef,
			Enabled:     vlan.Enabled,
			Broadcast:   vlan.Broadcast,
			ClientsOnly: vlan.ClientsOnly,
		})
	}

	return result
}

// convertMonitoring converts from CRD monitoring config to internal monitoring config
func convertMonitoring(src *v1alpha1.MonitoringConfig) ntp.MonitoringConfig {
	if src == nil {
		return ntp.MonitoringConfig{}
	}

	return ntp.MonitoringConfig{
		Enabled: src.Enabled,
		Offset: ntp.OffsetThresholds{
			WarningThreshold:  src.Offset.WarningThreshold,
			CriticalThreshold: src.Offset.CriticalThreshold,
		},
		SourcesMinimum: src.SourcesMinimum,
	}
}

// ConvertToStatus converts from internal status to CRD status
func ConvertToStatus(status *ntp.Status) v1alpha1.NTPServiceStatus {
	if status == nil {
		return v1alpha1.NTPServiceStatus{}
	}

	syncStatus := "Not Synchronized"
	if status.Synchronized {
		syncStatus = "Synchronized"
	}

	sources := make([]v1alpha1.SourceStatus, 0, len(status.Sources))
	for _, src := range status.Sources {
		sources = append(sources, v1alpha1.SourceStatus{
			Name:         src.Name,
			Type:         src.Type,
			Stratum:      src.Stratum,
			Offset:       src.Offset,
			Reachability: src.Reach,
			Selected:     src.Selected,
		})
	}

	return v1alpha1.NTPServiceStatus{
		SyncStatus:  syncStatus,
		Stratum:     status.Stratum,
		Offset:      status.Offset,
		Jitter:      status.Jitter,
		SourceCount: status.SourceCount,
		Sources:     sources,
	}
}