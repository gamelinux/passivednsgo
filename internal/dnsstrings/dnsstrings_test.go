package dnsstrings

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestDNSTypeString(t *testing.T) {
	tests := []struct {
		name     string
		input    layers.DNSType
		expected string
	}{
		{"Type A", layers.DNSTypeA, "A"},
		{"Type AAAA", layers.DNSTypeAAAA, "AAAA"},
		{"Type CNAME", layers.DNSTypeCNAME, "CNAME"},
		{"Type MX", layers.DNSTypeMX, "MX"},
		{"Type TXT", layers.DNSTypeTXT, "TXT"},
		{"Type Unknown", layers.DNSType(9999), "UNKNOWN(9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DNSTypeString(tt.input)
			if result != tt.expected {
				t.Errorf("DNSTypeString(%v) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDNSResponseCodeString(t *testing.T) {
	tests := []struct {
		name     string
		input    layers.DNSResponseCode
		expected string
	}{
		{"No Error", layers.DNSResponseCodeNoErr, "NOERROR"},
		{"NXDomain", layers.DNSResponseCodeNXDomain, "NXDOMAIN"},
		{"ServFail", layers.DNSResponseCodeServFail, "SERVFAIL"},
		{"Refused", layers.DNSResponseCodeRefused, "REFUSED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DNSResponseCodeString(tt.input)
			if result != tt.expected {
				t.Errorf("DNSResponseCodeString(%v) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}
