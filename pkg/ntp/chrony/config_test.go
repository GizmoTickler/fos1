package chrony

import (
	"strings"
	"testing"

	"github.com/GizmoTickler/fos1/pkg/ntp"
)

func TestConfigGenerator_Generate_BasicSources(t *testing.T) {
	gen := NewConfigGenerator()

	service := &ntp.NTPService{
		Name:    "test-ntp",
		Enabled: true,
		Sources: ntp.Sources{
			Pools: []ntp.PoolSource{
				{Name: "pool.ntp.org", Servers: 4, IBurst: true, Prefer: false},
				{Name: "time.cloudflare.com", Servers: 2, IBurst: true, Prefer: true},
			},
			Servers: []ntp.ServerSource{
				{Address: "time.google.com", IBurst: true, Prefer: false, MinPoll: 6, MaxPoll: 10},
			},
		},
		Server: ntp.ServerConfig{
			DriftFile: "/var/lib/chrony/drift",
			MakeStep:  ntp.StepConfig{Threshold: 1.0, Limit: 3},
			Local:     ntp.LocalClockConfig{Enabled: true, Stratum: 10},
		},
		Security: ntp.SecurityConfig{
			RateLimit: ntp.RateLimitConfig{Enabled: true, Interval: 3, Burst: 8},
			Access: []ntp.AccessRule{
				{Network: "192.168.0.0/16", Permission: "allow"},
				{Network: "0.0.0.0/0", Permission: "deny"},
			},
		},
	}

	config, err := gen.Generate(service)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify pool directives
	if !strings.Contains(config, "pool pool.ntp.org iburst maxsources 4") {
		t.Errorf("missing pool.ntp.org directive in config:\n%s", config)
	}
	if !strings.Contains(config, "pool time.cloudflare.com iburst prefer maxsources 2") {
		t.Errorf("missing time.cloudflare.com pool directive in config:\n%s", config)
	}

	// Verify server directives
	if !strings.Contains(config, "server time.google.com iburst minpoll 6 maxpoll 10") {
		t.Errorf("missing time.google.com server directive in config:\n%s", config)
	}

	// Verify server config
	if !strings.Contains(config, "driftfile /var/lib/chrony/drift") {
		t.Errorf("missing driftfile in config:\n%s", config)
	}
	if !strings.Contains(config, "makestep") {
		t.Errorf("missing makestep in config:\n%s", config)
	}
	if !strings.Contains(config, "local stratum 10") {
		t.Errorf("missing local stratum in config:\n%s", config)
	}

	// Verify rate limiting
	if !strings.Contains(config, "ratelimit interval 3 burst 8") {
		t.Errorf("missing ratelimit in config:\n%s", config)
	}

	// Verify access rules
	if !strings.Contains(config, "allow 192.168.0.0/16") {
		t.Errorf("missing allow rule in config:\n%s", config)
	}
	if !strings.Contains(config, "deny 0.0.0.0/0") {
		t.Errorf("missing deny rule in config:\n%s", config)
	}

	// Verify logging
	if !strings.Contains(config, "logdir /var/log/chrony") {
		t.Errorf("missing logdir in config:\n%s", config)
	}

	// NTS should NOT be present
	if strings.Contains(config, "ntsservercert") {
		t.Errorf("NTS should not appear when disabled, config:\n%s", config)
	}
}

func TestConfigGenerator_Generate_WithNTS(t *testing.T) {
	gen := NewConfigGenerator()

	service := &ntp.NTPService{
		Name:    "nts-ntp",
		Enabled: true,
		Sources: ntp.Sources{
			Servers: []ntp.ServerSource{
				{Address: "time.cloudflare.com", IBurst: true, Prefer: true},
			},
		},
		Server: ntp.ServerConfig{
			DriftFile: "/var/lib/chrony/drift",
			MakeStep:  ntp.StepConfig{Threshold: 0.5, Limit: 3},
		},
		Security: ntp.SecurityConfig{
			NTS: ntp.NTSConfig{
				Enabled:        true,
				ServerCertFile: "/etc/chrony/nts/server.crt",
				ServerKeyFile:  "/etc/chrony/nts/server.key",
				TrustedCerts:   "/etc/chrony/nts/ca-bundle.crt",
				NTSDumpDir:     "/var/lib/chrony/nts",
				NTSPort:        4460,
			},
		},
	}

	config, err := gen.Generate(service)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify NTS directives are present
	if !strings.Contains(config, "ntsdumpdir /var/lib/chrony/nts") {
		t.Errorf("missing ntsdumpdir in config:\n%s", config)
	}
	if !strings.Contains(config, "ntsservercert /etc/chrony/nts/server.crt") {
		t.Errorf("missing ntsservercert in config:\n%s", config)
	}
	if !strings.Contains(config, "ntsserverkey /etc/chrony/nts/server.key") {
		t.Errorf("missing ntsserverkey in config:\n%s", config)
	}
	if !strings.Contains(config, "ntstrustedcerts /etc/chrony/nts/ca-bundle.crt") {
		t.Errorf("missing ntstrustedcerts in config:\n%s", config)
	}
	if !strings.Contains(config, "ntsport 4460") {
		t.Errorf("missing ntsport in config:\n%s", config)
	}
	if !strings.Contains(config, "ntsprocesses 1") {
		t.Errorf("missing ntsprocesses in config:\n%s", config)
	}
}

func TestConfigGenerator_Generate_NTSDefaults(t *testing.T) {
	gen := NewConfigGenerator()

	service := &ntp.NTPService{
		Name:    "nts-defaults",
		Enabled: true,
		Sources: ntp.Sources{
			Servers: []ntp.ServerSource{
				{Address: "time.google.com", IBurst: true},
			},
		},
		Server: ntp.ServerConfig{
			DriftFile: "/var/lib/chrony/drift",
			MakeStep:  ntp.StepConfig{Threshold: 1.0, Limit: 3},
		},
		Security: ntp.SecurityConfig{
			NTS: ntp.NTSConfig{
				Enabled: true,
				// All other fields empty -- should use defaults
			},
		},
	}

	config, err := gen.Generate(service)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should use default paths
	if !strings.Contains(config, "ntsdumpdir /var/lib/chrony") {
		t.Errorf("missing default ntsdumpdir in config:\n%s", config)
	}
	if !strings.Contains(config, "ntsservercert /etc/chrony/nts/cert.pem") {
		t.Errorf("missing default ntsservercert in config:\n%s", config)
	}
	if !strings.Contains(config, "ntsserverkey /etc/chrony/nts/key.pem") {
		t.Errorf("missing default ntsserverkey in config:\n%s", config)
	}

	// TrustedCerts should NOT appear when empty
	if strings.Contains(config, "ntstrustedcerts") {
		t.Errorf("ntstrustedcerts should not appear when not configured, config:\n%s", config)
	}

	// NTSPort should NOT appear when 0
	if strings.Contains(config, "ntsport") {
		t.Errorf("ntsport should not appear when zero, config:\n%s", config)
	}
}

func TestConfigGenerator_Generate_HardwareSources(t *testing.T) {
	gen := NewConfigGenerator()

	service := &ntp.NTPService{
		Name:    "hw-ntp",
		Enabled: true,
		Sources: ntp.Sources{
			Hardware: ntp.HardwareSources{
				PPS: ntp.PPSSource{Enabled: true, Device: "/dev/pps0", Prefer: true},
				GPS: ntp.GPSSource{Enabled: true, Device: "/dev/ttyS0", RefClock: true, Prefer: false},
			},
		},
		Server: ntp.ServerConfig{
			DriftFile: "/var/lib/chrony/drift",
			MakeStep:  ntp.StepConfig{Threshold: 1.0, Limit: 3},
		},
		Security: ntp.SecurityConfig{},
	}

	config, err := gen.Generate(service)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(config, "refclock PPS /dev/pps0 prefer") {
		t.Errorf("missing PPS refclock in config:\n%s", config)
	}
	if !strings.Contains(config, "refclock SHM 0 refid GPS") {
		t.Errorf("missing GPS refclock in config:\n%s", config)
	}
}

func TestConfigGenerator_Generate_Authentication(t *testing.T) {
	gen := NewConfigGenerator()

	service := &ntp.NTPService{
		Name:    "auth-ntp",
		Enabled: true,
		Sources: ntp.Sources{
			Servers: []ntp.ServerSource{
				{Address: "10.0.0.1", IBurst: true},
			},
		},
		Server: ntp.ServerConfig{
			DriftFile: "/var/lib/chrony/drift",
			MakeStep:  ntp.StepConfig{Threshold: 1.0, Limit: 3},
		},
		Security: ntp.SecurityConfig{
			Authentication: ntp.AuthenticationConfig{
				Enabled: true,
				Keys: []ntp.AuthKey{
					{ID: 1, Type: "SHA256", Value: "secretkey"},
				},
			},
		},
	}

	config, err := gen.Generate(service)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(config, "keyfile /etc/chrony/chrony.keys") {
		t.Errorf("missing keyfile in config:\n%s", config)
	}
}

func TestConfigGenerator_Generate_NoLocalClock(t *testing.T) {
	gen := NewConfigGenerator()

	service := &ntp.NTPService{
		Name:    "no-local",
		Enabled: true,
		Sources: ntp.Sources{
			Servers: []ntp.ServerSource{
				{Address: "10.0.0.1", IBurst: true},
			},
		},
		Server: ntp.ServerConfig{
			DriftFile: "/var/lib/chrony/drift",
			MakeStep:  ntp.StepConfig{Threshold: 1.0, Limit: 3},
			Local:     ntp.LocalClockConfig{Enabled: false},
		},
		Security: ntp.SecurityConfig{},
	}

	config, err := gen.Generate(service)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if strings.Contains(config, "local stratum") {
		t.Errorf("local stratum should not appear when disabled, config:\n%s", config)
	}
}
