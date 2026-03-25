package coredns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testZone creates a Zone populated with various record types for testing.
func testZone() *Zone {
	return &Zone{
		Name:   "example.com",
		Domain: "example.com",
		SOA: &SOARecord{
			MName:   "ns1.example.com",
			RName:   "admin.example.com",
			Serial:  2025041901,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minimum: 3600,
		},
		Records: []*DNSRecord{
			{Name: "www", Type: "A", Value: "192.168.1.10", TTL: 3600},
			{Name: "mail", Type: "A", Value: "192.168.1.20", TTL: 3600},
			{Name: "api", Type: "AAAA", Value: "2001:db8::1", TTL: 7200},
			{Name: "blog", Type: "CNAME", Value: "www.example.com", TTL: 3600},
			{Name: "@", Type: "MX", Value: "10 mail.example.com", TTL: 3600},
			{Name: "@", Type: "TXT", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			{Name: "_sip._tcp", Type: "SRV", Value: "10 60 5060 sip.example.com", TTL: 3600},
			{Name: "10", Type: "PTR", Value: "www.example.com", TTL: 3600},
		},
		Updated:   time.Now(),
		ConfigGen: 5,
	}
}

func TestWriteZoneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.example.com")

	zone := testZone()
	err := WriteZoneFile(zone, path)
	require.NoError(t, err)

	// Read the file back and verify contents
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// Verify header
	assert.Contains(t, content, "; Zone file for example.com")
	assert.Contains(t, content, "; ConfigGen: 5")

	// Verify $TTL directive
	assert.Contains(t, content, "$TTL\t3600")

	// Verify SOA record
	assert.Contains(t, content, "example.com.\tIN\tSOA\tns1.example.com. admin.example.com.")
	assert.Contains(t, content, "2025041901\t; Serial")
	assert.Contains(t, content, "3600\t; Refresh")
	assert.Contains(t, content, "600\t; Retry")
	assert.Contains(t, content, "86400\t; Expire")
	assert.Contains(t, content, "3600\t; Minimum TTL")

	// Verify NS record
	assert.Contains(t, content, "example.com.\tIN\tNS\tns1.example.com.")

	// Verify A records
	assert.Contains(t, content, "mail\t3600\tIN\tA\t192.168.1.20")
	assert.Contains(t, content, "www\t3600\tIN\tA\t192.168.1.10")

	// Verify AAAA record
	assert.Contains(t, content, "api\t7200\tIN\tAAAA\t2001:db8::1")

	// Verify CNAME record
	assert.Contains(t, content, "blog\t3600\tIN\tCNAME\twww.example.com.")

	// Verify MX record
	assert.Contains(t, content, "@\t3600\tIN\tMX\t10\tmail.example.com.")

	// Verify TXT record
	assert.Contains(t, content, "IN\tTXT\t\"v=spf1 include:_spf.example.com ~all\"")

	// Verify SRV record
	assert.Contains(t, content, "_sip._tcp\t3600\tIN\tSRV\t10\t60\t5060\tsip.example.com.")

	// Verify PTR record
	assert.Contains(t, content, "10\t3600\tIN\tPTR\twww.example.com.")
}

func TestWriteZoneFile_Errors(t *testing.T) {
	// Nil zone
	err := WriteZoneFile(nil, "/tmp/test")
	assert.Error(t, err)

	// Empty path
	err = WriteZoneFile(&Zone{Name: "test"}, "")
	assert.Error(t, err)
}

func TestParseZoneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.example.com")

	// Write a zone file first
	zone := testZone()
	err := WriteZoneFile(zone, path)
	require.NoError(t, err)

	// Parse it back
	parsed, err := ParseZoneFile(path, "example.com")
	require.NoError(t, err)
	require.NotNil(t, parsed)

	assert.Equal(t, "example.com", parsed.Name)
	assert.Equal(t, "example.com", parsed.Domain)

	// Verify SOA was parsed
	require.NotNil(t, parsed.SOA)
	assert.Equal(t, "ns1.example.com", parsed.SOA.MName)
	assert.Equal(t, "admin.example.com", parsed.SOA.RName)
	assert.Equal(t, uint32(2025041901), parsed.SOA.Serial)
	assert.Equal(t, uint32(3600), parsed.SOA.Refresh)
	assert.Equal(t, uint32(600), parsed.SOA.Retry)
	assert.Equal(t, uint32(86400), parsed.SOA.Expire)
	assert.Equal(t, uint32(3600), parsed.SOA.Minimum)

	// Verify ConfigGen was parsed from comment
	assert.Equal(t, int64(5), parsed.ConfigGen)

	// Verify records were parsed (NS is skipped in parser)
	// We expect: A(www), A(mail), AAAA(api), CNAME(blog), MX(@), TXT(@), SRV(_sip._tcp), PTR(10)
	assert.Len(t, parsed.Records, 8)

	// Build a map of records by name+type for easy lookup
	recordMap := make(map[string]*DNSRecord)
	for _, r := range parsed.Records {
		key := r.Name + "/" + r.Type
		recordMap[key] = r
	}

	// Verify A records
	r, ok := recordMap["www/A"]
	require.True(t, ok, "www A record not found")
	assert.Equal(t, "192.168.1.10", r.Value)
	assert.Equal(t, int32(3600), r.TTL)

	r, ok = recordMap["mail/A"]
	require.True(t, ok, "mail A record not found")
	assert.Equal(t, "192.168.1.20", r.Value)

	// Verify AAAA record
	r, ok = recordMap["api/AAAA"]
	require.True(t, ok, "api AAAA record not found")
	assert.Equal(t, "2001:db8::1", r.Value)
	assert.Equal(t, int32(7200), r.TTL)

	// Verify CNAME record
	r, ok = recordMap["blog/CNAME"]
	require.True(t, ok, "blog CNAME record not found")
	assert.Equal(t, "www.example.com", r.Value)

	// Verify MX record
	r, ok = recordMap["@/MX"]
	require.True(t, ok, "@ MX record not found")
	assert.Equal(t, "10 mail.example.com", r.Value)

	// Verify TXT record
	r, ok = recordMap["@/TXT"]
	require.True(t, ok, "@ TXT record not found")
	assert.Equal(t, "v=spf1 include:_spf.example.com ~all", r.Value)

	// Verify SRV record
	r, ok = recordMap["_sip._tcp/SRV"]
	require.True(t, ok, "_sip._tcp SRV record not found")
	assert.Equal(t, "10 60 5060 sip.example.com", r.Value)

	// Verify PTR record
	r, ok = recordMap["10/PTR"]
	require.True(t, ok, "10 PTR record not found")
	assert.Equal(t, "www.example.com", r.Value)
}

func TestParseZoneFile_NotFound(t *testing.T) {
	_, err := ParseZoneFile("/nonexistent/path/db.test", "test")
	assert.Error(t, err)
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.example.com")

	original := testZone()
	err := WriteZoneFile(original, path)
	require.NoError(t, err)

	parsed, err := ParseZoneFile(path, "example.com")
	require.NoError(t, err)

	// Write again
	path2 := filepath.Join(dir, "db.example.com.roundtrip")
	err = WriteZoneFile(parsed, path2)
	require.NoError(t, err)

	// Parse again
	parsed2, err := ParseZoneFile(path2, "example.com")
	require.NoError(t, err)

	// Verify the data survived the round trip
	assert.Equal(t, parsed.Name, parsed2.Name)
	assert.Equal(t, parsed.Domain, parsed2.Domain)
	require.NotNil(t, parsed2.SOA)
	assert.Equal(t, parsed.SOA.Serial, parsed2.SOA.Serial)
	assert.Equal(t, parsed.SOA.Refresh, parsed2.SOA.Refresh)
	assert.Equal(t, parsed.SOA.Retry, parsed2.SOA.Retry)
	assert.Equal(t, parsed.SOA.Expire, parsed2.SOA.Expire)
	assert.Equal(t, parsed.SOA.Minimum, parsed2.SOA.Minimum)
	assert.Equal(t, len(parsed.Records), len(parsed2.Records))

	// Verify each record survived
	for i, rec := range parsed.Records {
		assert.Equal(t, rec.Name, parsed2.Records[i].Name, "record %d name mismatch", i)
		assert.Equal(t, rec.Type, parsed2.Records[i].Type, "record %d type mismatch", i)
		assert.Equal(t, rec.Value, parsed2.Records[i].Value, "record %d value mismatch", i)
		assert.Equal(t, rec.TTL, parsed2.Records[i].TTL, "record %d TTL mismatch", i)
	}
}

func TestIncrementSerial(t *testing.T) {
	now := time.Now()
	dateBase := uint32(now.Year()%10000)*1000000 +
		uint32(now.Month())*10000 +
		uint32(now.Day())*100

	t.Run("first serial of the day", func(t *testing.T) {
		zone := &Zone{
			SOA: &SOARecord{Serial: 0},
		}
		serial := IncrementSerial(zone)
		assert.Equal(t, dateBase+1, serial)
	})

	t.Run("increment within same day", func(t *testing.T) {
		zone := &Zone{
			SOA: &SOARecord{Serial: dateBase + 1},
		}
		serial := IncrementSerial(zone)
		assert.Equal(t, dateBase+2, serial)
	})

	t.Run("increment from previous day", func(t *testing.T) {
		zone := &Zone{
			SOA: &SOARecord{Serial: dateBase - 100 + 5}, // Yesterday
		}
		serial := IncrementSerial(zone)
		assert.Equal(t, dateBase+1, serial)
	})

	t.Run("nil zone", func(t *testing.T) {
		serial := IncrementSerial(nil)
		assert.Equal(t, uint32(0), serial)
	})

	t.Run("nil SOA", func(t *testing.T) {
		zone := &Zone{}
		serial := IncrementSerial(zone)
		assert.Equal(t, uint32(0), serial)
	})
}

func TestGenerateCorefile(t *testing.T) {
	zones := []*Zone{
		{Name: "example.com", Domain: "example.com"},
		{Name: "test.local", Domain: "test.local"},
	}

	corefile, err := GenerateCorefile(zones, ":5353", "/etc/coredns/zones")
	require.NoError(t, err)

	// Verify zone blocks
	assert.Contains(t, corefile, "example.com:5353 {")
	assert.Contains(t, corefile, "file /etc/coredns/zones/db.example.com")
	assert.Contains(t, corefile, "test.local:5353 {")
	assert.Contains(t, corefile, "file /etc/coredns/zones/db.test.local")

	// Verify reload plugin
	assert.Contains(t, corefile, "reload 5s")

	// Verify catch-all forward block
	assert.Contains(t, corefile, ".:5353 {")
	assert.Contains(t, corefile, "forward . /etc/resolv.conf")
	assert.Contains(t, corefile, "cache 30")
}

func TestGenerateCorefile_DefaultListenAddr(t *testing.T) {
	zones := []*Zone{
		{Name: "example.com", Domain: "example.com"},
	}

	corefile, err := GenerateCorefile(zones, "", "/etc/coredns")
	require.NoError(t, err)
	assert.Contains(t, corefile, "example.com:53 {")
}

func TestGenerateCorefile_Errors(t *testing.T) {
	// No zones
	_, err := GenerateCorefile(nil, ":53", "/etc/coredns")
	assert.Error(t, err)

	// No configDir
	_, err = GenerateCorefile([]*Zone{{Name: "test"}}, ":53", "")
	assert.Error(t, err)
}

func TestWriteAndReload(t *testing.T) {
	dir := t.TempDir()

	zones := []*Zone{
		{
			Name:   "example.com",
			Domain: "example.com",
			SOA: &SOARecord{
				MName:   "ns1.example.com",
				RName:   "admin.example.com",
				Serial:  2025041900,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minimum: 3600,
			},
			Records: []*DNSRecord{
				{Name: "www", Type: "A", Value: "10.0.0.1", TTL: 300},
			},
		},
	}

	err := WriteAndReload(zones, dir)
	require.NoError(t, err)

	// Verify the zone file was created
	zoneFilePath := filepath.Join(dir, "db.example.com")
	_, err = os.Stat(zoneFilePath)
	assert.NoError(t, err)

	// Verify the Corefile was created
	corefilePath := filepath.Join(dir, "Corefile")
	_, err = os.Stat(corefilePath)
	assert.NoError(t, err)

	// Verify the serial was incremented
	assert.NotEqual(t, uint32(2025041900), zones[0].SOA.Serial)

	// Verify the zone file can be parsed back
	parsed, err := ParseZoneFile(zoneFilePath, "example.com")
	require.NoError(t, err)
	assert.Len(t, parsed.Records, 1)
	assert.Equal(t, "www", parsed.Records[0].Name)
	assert.Equal(t, "10.0.0.1", parsed.Records[0].Value)
}

func TestWriteAndReload_Errors(t *testing.T) {
	// Empty zone dir
	err := WriteAndReload([]*Zone{{Name: "test"}}, "")
	assert.Error(t, err)

	// No zones
	err = WriteAndReload(nil, t.TempDir())
	assert.Error(t, err)
}

func TestReloadZones(t *testing.T) {
	dir := t.TempDir()

	// Create a fake zone file
	zoneFile := filepath.Join(dir, "db.example.com")
	err := os.WriteFile(zoneFile, []byte("; test"), 0644)
	require.NoError(t, err)

	// Set old modification time
	oldTime := time.Now().Add(-1 * time.Hour)
	err = os.Chtimes(zoneFile, oldTime, oldTime)
	require.NoError(t, err)

	// Reload
	err = ReloadZones(dir)
	require.NoError(t, err)

	// Verify the file was touched (mod time updated)
	info, err := os.Stat(zoneFile)
	require.NoError(t, err)
	assert.True(t, info.ModTime().After(oldTime))
}

func TestReloadZones_Errors(t *testing.T) {
	// Empty dir path
	err := ReloadZones("")
	assert.Error(t, err)

	// Non-existent dir
	err = ReloadZones("/nonexistent/path")
	assert.Error(t, err)

	// Dir with no zone files
	dir := t.TempDir()
	err = ReloadZones(dir)
	assert.Error(t, err)
}

func TestRecordTypes(t *testing.T) {
	// Test each record type individually for write/parse fidelity
	tests := []struct {
		name   string
		record *DNSRecord
	}{
		{"A record", &DNSRecord{Name: "host", Type: "A", Value: "10.0.0.1", TTL: 300}},
		{"AAAA record", &DNSRecord{Name: "host", Type: "AAAA", Value: "2001:db8::1", TTL: 300}},
		{"CNAME record", &DNSRecord{Name: "alias", Type: "CNAME", Value: "host.example.com", TTL: 300}},
		{"MX record", &DNSRecord{Name: "@", Type: "MX", Value: "10 mail.example.com", TTL: 300}},
		{"TXT record", &DNSRecord{Name: "@", Type: "TXT", Value: "v=spf1 -all", TTL: 300}},
		{"SRV record", &DNSRecord{Name: "_http._tcp", Type: "SRV", Value: "10 20 80 web.example.com", TTL: 300}},
		{"PTR record", &DNSRecord{Name: "1", Type: "PTR", Value: "host.example.com", TTL: 300}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "db.test")

			zone := &Zone{
				Name:   "test",
				Domain: "test",
				SOA: &SOARecord{
					MName:   "ns1.test",
					RName:   "admin.test",
					Serial:  1,
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minimum: 3600,
				},
				Records: []*DNSRecord{tc.record},
			}

			err := WriteZoneFile(zone, path)
			require.NoError(t, err)

			parsed, err := ParseZoneFile(path, "test")
			require.NoError(t, err)
			require.Len(t, parsed.Records, 1, "expected 1 record for %s", tc.name)

			got := parsed.Records[0]
			assert.Equal(t, tc.record.Name, got.Name, "name mismatch")
			assert.Equal(t, tc.record.Type, got.Type, "type mismatch")
			assert.Equal(t, tc.record.Value, got.Value, "value mismatch")
			assert.Equal(t, tc.record.TTL, got.TTL, "TTL mismatch")
		})
	}
}

func TestEnsureTrailingDot(t *testing.T) {
	assert.Equal(t, "example.com.", ensureTrailingDot("example.com"))
	assert.Equal(t, "example.com.", ensureTrailingDot("example.com."))
	assert.Equal(t, ".", ensureTrailingDot(""))
}

func TestStripTrailingDot(t *testing.T) {
	assert.Equal(t, "example.com", stripTrailingDot("example.com."))
	assert.Equal(t, "example.com", stripTrailingDot("example.com"))
}

func TestZoneFileName(t *testing.T) {
	assert.Equal(t, "db.example.com", zoneFileName("example.com"))
	assert.Equal(t, "db.example.com", zoneFileName("example.com."))
}

func TestIsZoneFile(t *testing.T) {
	assert.True(t, isZoneFile("db.example.com"))
	assert.True(t, isZoneFile("db.local"))
	assert.False(t, isZoneFile("Corefile"))
	assert.False(t, isZoneFile("db."))
	assert.False(t, isZoneFile("db"))
	assert.False(t, isZoneFile(""))
}

func TestWriteZoneFile_NoSOA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.test")

	zone := &Zone{
		Name:    "test",
		Domain:  "test",
		Records: []*DNSRecord{{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 60}},
	}

	err := WriteZoneFile(zone, path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// Should still have the record
	assert.Contains(t, content, "www\t60\tIN\tA\t1.2.3.4")
	// Should not have SOA
	assert.NotContains(t, content, "SOA")
}

func TestWriteZoneFile_NoTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.test")

	zone := &Zone{
		Name:   "test",
		Domain: "test",
		SOA: &SOARecord{
			MName: "ns1.test", RName: "admin.test",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 3600,
		},
		Records: []*DNSRecord{{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 0}},
	}

	err := WriteZoneFile(zone, path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// Record with TTL 0 should omit the TTL field
	assert.Contains(t, content, "www\tIN\tA\t1.2.3.4")
	// Make sure it's not "www\t0\tIN"
	assert.NotContains(t, content, "www\t0\tIN")
}

func TestParseRecordLine(t *testing.T) {
	tests := []struct {
		line     string
		wantNil  bool
		wantName string
		wantType string
	}{
		{"www\t3600\tIN\tA\t1.2.3.4", false, "www", "A"},
		{"www\tIN\tA\t1.2.3.4", false, "www", "A"},
		{"; comment line", true, "", ""},
		{"", true, "", ""},
		{"short", true, "", ""},
	}

	for _, tc := range tests {
		rec := parseRecordLine(tc.line, "test")
		if tc.wantNil {
			assert.Nil(t, rec, "expected nil for: %q", tc.line)
		} else {
			require.NotNil(t, rec, "expected record for: %q", tc.line)
			assert.Equal(t, tc.wantName, rec.Name)
			assert.Equal(t, tc.wantType, rec.Type)
		}
	}
}

func TestGenerateCorefile_UsesZoneDomain(t *testing.T) {
	zones := []*Zone{
		{Name: "myzone", Domain: "custom.domain.com"},
	}
	corefile, err := GenerateCorefile(zones, ":53", "/zones")
	require.NoError(t, err)
	assert.Contains(t, corefile, "custom.domain.com:53 {")
	assert.Contains(t, corefile, "db.custom.domain.com")
}

func TestGenerateCorefile_FallsBackToName(t *testing.T) {
	zones := []*Zone{
		{Name: "myzone", Domain: ""},
	}
	corefile, err := GenerateCorefile(zones, ":53", "/zones")
	require.NoError(t, err)
	assert.Contains(t, corefile, "myzone:53 {")
}

func TestMultipleRecordsSameType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.test")

	zone := &Zone{
		Name:   "test",
		Domain: "test",
		SOA: &SOARecord{
			MName: "ns1.test", RName: "admin.test",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 3600,
		},
		Records: []*DNSRecord{
			{Name: "a", Type: "A", Value: "1.1.1.1", TTL: 300},
			{Name: "b", Type: "A", Value: "2.2.2.2", TTL: 300},
			{Name: "c", Type: "A", Value: "3.3.3.3", TTL: 300},
		},
	}

	err := WriteZoneFile(zone, path)
	require.NoError(t, err)

	parsed, err := ParseZoneFile(path, "test")
	require.NoError(t, err)

	// All three A records should be present
	aRecords := 0
	for _, r := range parsed.Records {
		if r.Type == "A" {
			aRecords++
		}
	}
	assert.Equal(t, 3, aRecords)
}

func TestIsClass(t *testing.T) {
	assert.True(t, isClass("IN"))
	assert.True(t, isClass("in"))
	assert.True(t, isClass("CH"))
	assert.False(t, isClass("A"))
	assert.False(t, isClass("www"))
}

func TestContainsString(t *testing.T) {
	slice := []string{"A", "AAAA", "CNAME"}
	assert.True(t, containsString(slice, "A"))
	assert.True(t, containsString(slice, "CNAME"))
	assert.False(t, containsString(slice, "MX"))
	assert.False(t, containsString(nil, "A"))
}

func TestGroupRecordsByType(t *testing.T) {
	records := []*DNSRecord{
		{Name: "b", Type: "A", Value: "2.2.2.2"},
		{Name: "a", Type: "A", Value: "1.1.1.1"},
		{Name: "mail", Type: "MX", Value: "10 mail.test"},
	}

	grouped := groupRecordsByType(records)
	assert.Len(t, grouped["A"], 2)
	assert.Len(t, grouped["MX"], 1)

	// Verify A records are sorted by name
	assert.Equal(t, "a", grouped["A"][0].Name)
	assert.Equal(t, "b", grouped["A"][1].Name)
}

func TestControllerLoadConfiguration_FromDisk(t *testing.T) {
	dir := t.TempDir()

	// Write a zone file to the directory
	zone := &Zone{
		Name:   "test.local",
		Domain: "test.local",
		SOA: &SOARecord{
			MName: "ns1.test.local", RName: "admin.test.local",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 3600,
		},
		Records: []*DNSRecord{
			{Name: "www", Type: "A", Value: "10.0.0.1", TTL: 300},
		},
	}
	err := WriteZoneFile(zone, filepath.Join(dir, "db.test.local"))
	require.NoError(t, err)

	// Create controller and load
	ctrl, err := NewController(dir, dir)
	require.NoError(t, err)

	err = ctrl.loadConfiguration()
	require.NoError(t, err)

	// Should have loaded the zone from disk
	loaded, ok := ctrl.zones["test.local"]
	require.True(t, ok, "test.local zone should be loaded")
	assert.Len(t, loaded.Records, 1)
	assert.Equal(t, "www", loaded.Records[0].Name)
}

func TestControllerLoadConfiguration_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	ctrl, err := NewController(dir, dir)
	require.NoError(t, err)

	err = ctrl.loadConfiguration()
	require.NoError(t, err)

	// Should have default zones
	_, ok := ctrl.zones["local"]
	assert.True(t, ok, "default local zone should exist")
	_, ok = ctrl.ptrZones["in-addr.arpa"]
	assert.True(t, ok, "default in-addr.arpa zone should exist")
}

func TestControllerLoadConfiguration_NonexistentDir(t *testing.T) {
	ctrl, err := NewController("/tmp/coredns-test-nonexistent-dir-12345", "/tmp/coredns-test-nonexistent-dir-12345")
	require.NoError(t, err)

	err = ctrl.loadConfiguration()
	require.NoError(t, err)

	// Should have default zones
	_, ok := ctrl.zones["local"]
	assert.True(t, ok)
}

func TestControllerSaveConfiguration(t *testing.T) {
	dir := t.TempDir()

	ctrl, err := NewController(dir, dir)
	require.NoError(t, err)

	// Add a zone
	ctrl.zones["test.com"] = &Zone{
		Name:   "test.com",
		Domain: "test.com",
		SOA: &SOARecord{
			MName: "ns1.test.com", RName: "admin.test.com",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 3600,
		},
		Records: []*DNSRecord{
			{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 300},
		},
	}

	err = ctrl.saveConfiguration()
	require.NoError(t, err)

	// Verify zone file was written
	path := filepath.Join(dir, "db.test.com")
	_, err = os.Stat(path)
	assert.NoError(t, err)

	// Verify it can be parsed
	parsed, err := ParseZoneFile(path, "test.com")
	require.NoError(t, err)
	assert.Len(t, parsed.Records, 1)
	assert.Equal(t, "www", parsed.Records[0].Name)
}

func TestControllerReverseZoneLoadedAsPTR(t *testing.T) {
	dir := t.TempDir()

	// Write a reverse zone file
	zone := &Zone{
		Name:   "168.192.in-addr.arpa",
		Domain: "168.192.in-addr.arpa",
		SOA: &SOARecord{
			MName: "ns1.168.192.in-addr.arpa", RName: "admin.168.192.in-addr.arpa",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 3600,
		},
		Records: []*DNSRecord{
			{Name: "1.1", Type: "PTR", Value: "host.example.com", TTL: 300},
		},
	}
	err := WriteZoneFile(zone, filepath.Join(dir, "db.168.192.in-addr.arpa"))
	require.NoError(t, err)

	ctrl, err := NewController(dir, dir)
	require.NoError(t, err)

	err = ctrl.loadConfiguration()
	require.NoError(t, err)

	// Should be loaded as a ptrZone, not a regular zone
	_, ok := ctrl.ptrZones["168.192.in-addr.arpa"]
	assert.True(t, ok, "reverse zone should be in ptrZones")
	_, ok = ctrl.zones["168.192.in-addr.arpa"]
	assert.False(t, ok, "reverse zone should NOT be in zones")
}

func TestParseSOALines(t *testing.T) {
	lines := []string{
		"example.com.\tIN\tSOA\tns1.example.com. admin.example.com. (",
		"\t\t\t\t2025041901\t; Serial",
		"\t\t\t\t3600\t; Refresh",
		"\t\t\t\t600\t; Retry",
		"\t\t\t\t86400\t; Expire",
		"\t\t\t\t3600\t; Minimum TTL",
		"\t\t\t\t)",
	}

	soa := parseSOALines(lines)
	require.NotNil(t, soa)
	assert.Equal(t, "ns1.example.com", soa.MName)
	assert.Equal(t, "admin.example.com", soa.RName)
	assert.Equal(t, uint32(2025041901), soa.Serial)
	assert.Equal(t, uint32(3600), soa.Refresh)
	assert.Equal(t, uint32(600), soa.Retry)
	assert.Equal(t, uint32(86400), soa.Expire)
	assert.Equal(t, uint32(3600), soa.Minimum)
}

// Ensure we don't leave unused import warnings (strings is used if needed).
var _ = strings.TrimSpace
