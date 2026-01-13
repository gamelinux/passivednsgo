package dnsstrings

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket/layers"
	"strconv"
)

// DNSType represents a DNS record type for various DNSSEC or general DNS records.
type DNSType uint16

// DNS record types supported in the package.
const (
	DNSTypeDNAME      DNSType = 39 // Alias for a name and all its subnames
	DNSTypeDNSKEY     DNSType = 48 // DNSSEC key record
	DNSTypeDS         DNSType = 43 // DNSSEC signing key identifier for a delegated zone
	DNSTypeNSEC       DNSType = 47 // DNSSEC proof of nonexistence
	DNSTypeNSEC3      DNSType = 50 // DNSSEC extension with enhanced privacy
	DNSTypeNSEC3PARAM DNSType = 51 // Parameters for NSEC3 DNSSEC extension
	DNSTypeRRSIG      DNSType = 46 // DNSSEC signature for secured record sets
	DNSTypeHTTPS      DNSType = 65 // HTTPS
)

// DNSTypeString converts a DNSType value to its string representation.
func DNSTypeString(dnsType layers.DNSType) string {
	switch dnsType {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSType(DNSTypeHTTPS):
		return "HTTPS"
	case layers.DNSTypeHINFO:
		return "HINFO"
	case layers.DNSTypeMB:
		return "MB"
	case layers.DNSTypeMD:
		return "MD"
	case layers.DNSTypeMF:
		return "MF"
	case layers.DNSTypeMG:
		return "MG"
	case layers.DNSTypeMINFO:
		return "MINFO"
	case layers.DNSTypeMR:
		return "MR"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeNULL:
		return "NULL"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeWKS:
		return "WKS"
	case layers.DNSType(DNSTypeRRSIG):
		return "RRSIG"
	default:
		return "UNKNOWN(" + strconv.Itoa(int(dnsType)) + ")"
	}
}

// DNSResourceRecordString formats DNS resource records into a string based on type.
func DNSResourceRecordString(record layers.DNSResourceRecord) string {
	switch record.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		return record.IP.String()
	case layers.DNSTypeCNAME:
		return string(record.CNAME)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s", record.MX.Preference, record.MX.Name)
	case layers.DNSTypeNS:
		return string(record.NS)
	case layers.DNSTypePTR:
		return string(record.PTR)
	case layers.DNSTypeSOA:
		return fmt.Sprintf("%s %v %v %v %v %v", record.SOA.RName, record.SOA.Serial, record.SOA.Refresh, record.SOA.Retry, record.SOA.Expire, record.SOA.Minimum)
	case layers.DNSTypeSRV:
		return fmt.Sprintf("%d %d %d %s", record.SRV.Priority, record.SRV.Weight, record.SRV.Port, record.SRV.Name)
	case layers.DNSTypeTXT:
		return string(record.TXT)
	default:
		return hex.EncodeToString([]byte(string(record.Data)))
	}
}

// DNSResponseCodeString converts a DNS response code to its string representation.
func DNSResponseCodeString(code layers.DNSResponseCode) string {
	switch code {
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	case layers.DNSResponseCodeYXDomain:
		return "YXDOMAIN"
	case layers.DNSResponseCodeYXRRSet:
		return "YXRRSET"
	case layers.DNSResponseCodeNXRRSet:
		return "NXRRSET"
	case layers.DNSResponseCodeNotAuth:
		return "NOTAUTH"
	case layers.DNSResponseCodeNotZone:
		return "NOTZONE"
	case layers.DNSResponseCodeBadVers:
		return "BADVERS"
	case layers.DNSResponseCodeBadKey:
		return "BADKEY"
	case layers.DNSResponseCodeBadTime:
		return "BADTIME"
	case layers.DNSResponseCodeBadMode:
		return "BADMODE"
	case layers.DNSResponseCodeBadName:
		return "BADNAME"
	case layers.DNSResponseCodeBadAlg:
		return "BADALG"
	case layers.DNSResponseCodeBadTruc:
		return "BADTRUC"
	default:
		return "NOERROR"
	}
}

// DNSOpCodeString provides a string representation of DNS operation codes.
func DNSOpCodeString(opCode layers.DNSOpCode) string {
	switch opCode {
	case layers.DNSOpCodeQuery:
		return "QUERY"
	case layers.DNSOpCodeIQuery:
		return "IQUERY"
	case layers.DNSOpCodeStatus:
		return "STATUS"
	case layers.DNSOpCodeNotify:
		return "NOTIFY"
	case layers.DNSOpCodeUpdate:
		return "UPDATE"
	default:
		return "UNKNOWN"
	}
}
