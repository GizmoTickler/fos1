package api

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/GizmoTickler/fos1/pkg/ntp"
	"github.com/GizmoTickler/fos1/pkg/ntp/api/v1alpha1"
)

func TestConvertToInternal(t *testing.T) {
	crd := &v1alpha1.NTPService{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ntp", Namespace: "default"},
		Spec: v1alpha1.NTPServiceSpec{
			Enabled: true,
			Sources: v1alpha1.Sources{
				Pools: []v1alpha1.PoolSource{
					{Name: "pool.ntp.org", Servers: 4, IBurst: true, Prefer: false},
				},
				Servers: []v1alpha1.ServerSource{
					{Address: "time.google.com", IBurst: true, MinPoll: 6, MaxPoll: 10},
				},
				Hardware: v1alpha1.HardwareSources{
					PPS: v1alpha1.PPSSource{Enabled: true, Device: "/dev/pps0", Prefer: true},
				},
			},
			Server: v1alpha1.ServerConfig{
				Stratum:   2,
				DriftFile: "/var/lib/chrony/drift",
				MakeStep:  v1alpha1.StepConfig{Threshold: 1.0, Limit: 3},
				Local:     v1alpha1.LocalClockConfig{Enabled: true, Stratum: 10},
			},
			Security: v1alpha1.SecurityConfig{
				NTS: v1alpha1.NTSConfig{
					Enabled:        true,
					ServerCertFile: "/etc/chrony/nts/cert.pem",
					ServerKeyFile:  "/etc/chrony/nts/key.pem",
					TrustedCerts:   "/etc/pki/ca-bundle.crt",
					NTSDumpDir:     "/var/lib/chrony",
					NTSPort:        4460,
				},
				Authentication: v1alpha1.AuthConfig{
					Enabled: true,
					Keys: []v1alpha1.AuthKey{
						{ID: 1, Type: "SHA256", Value: "abc123"},
					},
				},
				RateLimit: v1alpha1.RateLimitConfig{Enabled: true, Interval: 3, Burst: 8},
				Access: []v1alpha1.AccessRule{
					{Network: "192.168.0.0/16", Permission: "allow"},
				},
			},
			VLANConfig: []v1alpha1.VLANConfig{
				{
					VLANRef:     "vlan-10",
					Enabled:     true,
					Broadcast:   true,
					ClientsOnly: false,
					IPv4Address: "192.168.10.1",
					IPv6Address: "fd00:10::1",
					Domain:      "home.lan",
				},
			},
			Monitoring: v1alpha1.MonitoringConfig{
				Enabled:        true,
				SourcesMinimum: 3,
				Offset: v1alpha1.OffsetThresholds{
					WarningThreshold:  100,
					CriticalThreshold: 1000,
				},
			},
		},
	}

	internal := ConvertToInternal(crd)
	if internal == nil {
		t.Fatal("ConvertToInternal returned nil")
	}

	if internal.Name != "test-ntp" {
		t.Errorf("Name = %q, want %q", internal.Name, "test-ntp")
	}
	if !internal.Enabled {
		t.Error("Enabled should be true")
	}

	// Sources
	if len(internal.Sources.Pools) != 1 || internal.Sources.Pools[0].Name != "pool.ntp.org" {
		t.Errorf("Pools = %+v, want pool.ntp.org", internal.Sources.Pools)
	}
	if len(internal.Sources.Servers) != 1 || internal.Sources.Servers[0].Address != "time.google.com" {
		t.Errorf("Servers = %+v, want time.google.com", internal.Sources.Servers)
	}
	if !internal.Sources.Hardware.PPS.Enabled {
		t.Error("PPS should be enabled")
	}

	// NTS
	if !internal.Security.NTS.Enabled {
		t.Error("NTS should be enabled")
	}
	if internal.Security.NTS.ServerCertFile != "/etc/chrony/nts/cert.pem" {
		t.Errorf("NTS ServerCertFile = %q", internal.Security.NTS.ServerCertFile)
	}
	if internal.Security.NTS.TrustedCerts != "/etc/pki/ca-bundle.crt" {
		t.Errorf("NTS TrustedCerts = %q", internal.Security.NTS.TrustedCerts)
	}
	if internal.Security.NTS.NTSPort != 4460 {
		t.Errorf("NTS Port = %d, want 4460", internal.Security.NTS.NTSPort)
	}

	// VLAN
	if len(internal.VLANConfig) != 1 {
		t.Fatalf("VLANConfig len = %d, want 1", len(internal.VLANConfig))
	}
	vlan := internal.VLANConfig[0]
	if vlan.IPv4Address != "192.168.10.1" {
		t.Errorf("VLAN IPv4Address = %q", vlan.IPv4Address)
	}
	if vlan.IPv6Address != "fd00:10::1" {
		t.Errorf("VLAN IPv6Address = %q", vlan.IPv6Address)
	}
	if vlan.Domain != "home.lan" {
		t.Errorf("VLAN Domain = %q", vlan.Domain)
	}

	// Auth
	if !internal.Security.Authentication.Enabled {
		t.Error("Authentication should be enabled")
	}
	if len(internal.Security.Authentication.Keys) != 1 {
		t.Errorf("Keys len = %d", len(internal.Security.Authentication.Keys))
	}
}

func TestConvertToInternal_Nil(t *testing.T) {
	if result := ConvertToInternal(nil); result != nil {
		t.Errorf("ConvertToInternal(nil) = %v, want nil", result)
	}
}

func TestConvertToStatus(t *testing.T) {
	status := &ntp.Status{
		Running:      true,
		Synchronized: true,
		Stratum:      2,
		Offset:       0.5,
		Jitter:       0.1,
		SourceCount:  3,
		Sources: []ntp.Source{
			{Name: "time.google.com", Type: "Server", Stratum: 1, Offset: 0.3, Reach: 377, Selected: true},
			{Name: "pool.ntp.org", Type: "Server", Stratum: 2, Offset: 0.8, Reach: 377, Selected: false},
		},
	}

	crdStatus := ConvertToStatus(status)

	if crdStatus.SyncStatus != "Synchronized" {
		t.Errorf("SyncStatus = %q, want Synchronized", crdStatus.SyncStatus)
	}
	if crdStatus.Stratum != 2 {
		t.Errorf("Stratum = %d, want 2", crdStatus.Stratum)
	}
	if crdStatus.Offset != 0.5 {
		t.Errorf("Offset = %f, want 0.5", crdStatus.Offset)
	}
	if crdStatus.SourceCount != 3 {
		t.Errorf("SourceCount = %d, want 3", crdStatus.SourceCount)
	}
	if len(crdStatus.Sources) != 2 {
		t.Fatalf("Sources len = %d, want 2", len(crdStatus.Sources))
	}
	if !crdStatus.Sources[0].Selected {
		t.Error("First source should be selected")
	}
}

func TestConvertToStatus_NotSynchronized(t *testing.T) {
	status := &ntp.Status{
		Running:      true,
		Synchronized: false,
		Stratum:      0,
	}

	crdStatus := ConvertToStatus(status)
	if crdStatus.SyncStatus != "Not Synchronized" {
		t.Errorf("SyncStatus = %q, want 'Not Synchronized'", crdStatus.SyncStatus)
	}
}

func TestConvertToStatus_Nil(t *testing.T) {
	crdStatus := ConvertToStatus(nil)
	if crdStatus.SyncStatus != "" {
		t.Errorf("ConvertToStatus(nil) SyncStatus = %q, want empty", crdStatus.SyncStatus)
	}
}
