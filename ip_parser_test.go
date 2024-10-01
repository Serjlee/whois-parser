package whoisparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseIPWhois tests the ParseIPWhois function with various inputs.
func TestParseIPWhois(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected WhoisInfo
		hasError bool
	}{
		{
			name: "Valid IP WHOIS",
			input: `
NetRange:       99.10.64.0 - 99.75.191.255
CIDR:           99.74.0.0/16, 99.75.0.0/17, 99.72.0.0/15, 99.16.0.0/12, 99.11.0.0/16, 99.64.0.0/13, 99.32.0.0/11, 99.75.128.0/18, 99.10.128.0/17, 99.12.0.0/14, 99.10.64.0/18
NetName:        SBCIS-SBIS
NetHandle:      NET-99-10-64-0-1
Parent:         NET99 (NET-99-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS7132
Organization:   AT&T Corp. (AC-3280)
RegDate:        2008-02-25
Updated:        2018-07-19
Ref:            https://rdap.arin.net/registry/ip/99.10.64.0
`,
			expected: WhoisInfo{
				IP: &IPInfo{
					Networks: []*Network{
						{
							Range:            "99.10.64.0 - 99.75.191.255",
							CIDR:             []string{"99.74.0.0/16", "99.75.0.0/17", "99.72.0.0/15", "99.16.0.0/12", "99.11.0.0/16", "99.64.0.0/13", "99.32.0.0/11", "99.75.128.0/18", "99.10.128.0/17", "99.12.0.0/14", "99.10.64.0/18"},
							Name:             "SBCIS-SBIS",
							Handle:           "NET-99-10-64-0-1",
							Parent:           "NET99 (NET-99-0-0-0-0)",
							Type:             "Direct Allocation",
							OriginAS:         "AS7132",
							RegDate:          "2008-02-25",
							Updated:          "2018-07-19",
							Ref:              "https://rdap.arin.net/registry/ip/99.10.64.0",
							OrganizationName: "AT&T Corp. (AC-3280)",
						},
					},
				},
			},
			hasError: false,
		},
		{
			name:     "Invalid IP WHOIS",
			input:    "This is not a valid IP WHOIS response",
			expected: WhoisInfo{},
			hasError: true, // Ensure the parser returns an error for invalid inputs
		},
		{
			name: "IP WHOIS with Multiple Networks and Contacts",
			input: `
NetRange:       192.0.2.0 - 192.0.2.255
CIDR:           192.0.2.0/24
NetName:        TEST-NET-1
NetHandle:      NET-192-0-2-0-1
Parent:         NET-192-0-0-0-0
NetType:        Direct Allocation
OriginAS:       AS99999
Organization:   Example Corp. (EX-1234)
RegDate:        2020-01-01
Updated:        2023-01-01
Ref:            https://rdap.arin.net/registry/ip/192.0.2.0

OrgName:        Example Corp.
OrgId:          EX-1234
Address:        123 Example Street
Address:        Suite 100
City:           Exampleville
StateProv:      EX
PostalCode:     12345
Country:        US
RegDate:        2020-01-01
Updated:        2023-01-01
Comment:        This is a test network.
Ref:            https://rdap.arin.net/registry/entity/EX-1234

OrgAbuseHandle: ABUSE1-ARIN
OrgAbuseName:   Abuse Team
OrgAbusePhone:  +1-800-123-4567
OrgAbuseEmail:  abuse@example.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE1-ARIN

OrgRoutingHandle: ROUTE1-ARIN
OrgRoutingName:   Routing Department
OrgRoutingPhone:  +1-800-765-4321
OrgRoutingEmail:  routing@example.com
OrgRoutingRef:    https://rdap.arin.net/registry/entity/ROUTE1-ARIN

OrgTechHandle: TECH1-ARIN
OrgTechName:   Technical Support
OrgTechPhone:  +1-800-111-2222
OrgTechEmail:  tech@example.com
OrgTechRef:    https://rdap.arin.net/registry/entity/TECH1-ARIN
`,
			expected: WhoisInfo{
				IP: &IPInfo{
					Networks: []*Network{
						{
							Range:            "192.0.2.0 - 192.0.2.255",
							CIDR:             []string{"192.0.2.0/24"},
							Name:             "TEST-NET-1",
							Handle:           "NET-192-0-2-0-1",
							Parent:           "NET-192-0-0-0-0",
							Type:             "Direct Allocation",
							OriginAS:         "AS99999",
							RegDate:          "2020-01-01",
							Updated:          "2023-01-01",
							Ref:              "https://rdap.arin.net/registry/ip/192.0.2.0",
							OrganizationName: "Example Corp. (EX-1234)",
							Organization: &Contact{
								Organization:     "Example Corp.",
								ID:               "EX-1234",
								RegistrationDate: "2020-01-01",
								Street:           "123 Example Street\nSuite 100",
								City:             "Exampleville",
								Province:         "EX",
								PostalCode:       "12345",
								Country:          "US",
								Comment:          "This is a test network.",
								ReferralURL:      "https://rdap.arin.net/registry/entity/EX-1234",
							},
						},
					},
					Abuse: &Contact{
						ID:          "ABUSE1-ARIN",
						Name:        "Abuse Team",
						Phone:       "+1-800-123-4567",
						Email:       "abuse@example.com",
						ReferralURL: "https://rdap.arin.net/registry/entity/ABUSE1-ARIN",
					},
					Routing: &Contact{
						ID:          "ROUTE1-ARIN",
						Name:        "Routing Department",
						Phone:       "+1-800-765-4321",
						Email:       "routing@example.com",
						ReferralURL: "https://rdap.arin.net/registry/entity/ROUTE1-ARIN",
					},
					Technical: &Contact{
						ID:          "TECH1-ARIN",
						Name:        "Technical Support",
						Phone:       "+1-800-111-2222",
						Email:       "tech@example.com",
						ReferralURL: "https://rdap.arin.net/registry/entity/TECH1-ARIN",
					},
				},
			},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIPWhois(tt.input)
			if tt.hasError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				// Compare Networks
				assert.Equal(t, len(tt.expected.IP.Networks), len(result.IP.Networks), "Number of networks mismatch")
				for i, expectedNetwork := range tt.expected.IP.Networks {
					if i >= len(result.IP.Networks) {
						t.Errorf("Expected more networks, missing network at index %d", i)
						continue
					}
					actualNetwork := result.IP.Networks[i]
					assert.Equalf(t, expectedNetwork.Range, actualNetwork.Range, "Network Range mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.CIDR, actualNetwork.CIDR, "Network CIDR mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.Name, actualNetwork.Name, "Network Name mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.Handle, actualNetwork.Handle, "Network Handle mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.Parent, actualNetwork.Parent, "Network Parent mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.Type, actualNetwork.Type, "Network Type mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.OriginAS, actualNetwork.OriginAS, "Network OriginAS mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.RegDate, actualNetwork.RegDate, "Network RegDate mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.Updated, actualNetwork.Updated, "Network Updated mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.Ref, actualNetwork.Ref, "Network Ref mismatch at index %d", i)
					assert.Equalf(t, expectedNetwork.OrganizationName, actualNetwork.OrganizationName, "Network OrganizationName mismatch at index %d", i)

					// Compare Organization
					if expectedNetwork.Organization != nil {
						if actualNetwork.Organization == nil {
							t.Errorf("Expected Organization in network %d, but got nil", i)
						} else {
							assert.Equalf(t, expectedNetwork.Organization.Organization, actualNetwork.Organization.Organization, "Organization Name mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.ID, actualNetwork.Organization.ID, "Organization ID mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.RegistrationDate, actualNetwork.Organization.RegistrationDate, "Organization RegistrationDate mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.Street, actualNetwork.Organization.Street, "Organization Street mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.City, actualNetwork.Organization.City, "Organization City mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.Province, actualNetwork.Organization.Province, "Organization Province mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.PostalCode, actualNetwork.Organization.PostalCode, "Organization PostalCode mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.Country, actualNetwork.Organization.Country, "Organization Country mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.Comment, actualNetwork.Organization.Comment, "Organization Comment mismatch at network %d", i)
							assert.Equalf(t, expectedNetwork.Organization.ReferralURL, actualNetwork.Organization.ReferralURL, "Organization ReferralURL mismatch at network %d", i)
						}
					} else {
						if actualNetwork.Organization != nil {
							t.Errorf("Did not expect Organization in network %d, but got one", i)
						}
					}
				}

				// Compare Abuse Contact
				if tt.expected.IP.Abuse != nil {
					if result.IP.Abuse == nil {
						t.Errorf("Expected Abuse contact, but got nil")
					} else {
						assert.Equal(t, tt.expected.IP.Abuse.ID, result.IP.Abuse.ID, "Abuse Contact ID mismatch")
						assert.Equal(t, tt.expected.IP.Abuse.Name, result.IP.Abuse.Name, "Abuse Contact Name mismatch")
						assert.Equal(t, tt.expected.IP.Abuse.Phone, result.IP.Abuse.Phone, "Abuse Contact Phone mismatch")
						assert.Equal(t, tt.expected.IP.Abuse.Email, result.IP.Abuse.Email, "Abuse Contact Email mismatch")
						assert.Equal(t, tt.expected.IP.Abuse.ReferralURL, result.IP.Abuse.ReferralURL, "Abuse Contact ReferralURL mismatch")
					}
				}

				// Compare Routing Contact
				if tt.expected.IP.Routing != nil {
					if result.IP.Routing == nil {
						t.Errorf("Expected Routing contact, but got nil")
					} else {
						assert.Equal(t, tt.expected.IP.Routing.ID, result.IP.Routing.ID, "Routing Contact ID mismatch")
						assert.Equal(t, tt.expected.IP.Routing.Name, result.IP.Routing.Name, "Routing Contact Name mismatch")
						assert.Equal(t, tt.expected.IP.Routing.Phone, result.IP.Routing.Phone, "Routing Contact Phone mismatch")
						assert.Equal(t, tt.expected.IP.Routing.Email, result.IP.Routing.Email, "Routing Contact Email mismatch")
						assert.Equal(t, tt.expected.IP.Routing.ReferralURL, result.IP.Routing.ReferralURL, "Routing Contact ReferralURL mismatch")
					}
				}

				// Compare Technical Contact
				if tt.expected.IP.Technical != nil {
					if result.IP.Technical == nil {
						t.Errorf("Expected Technical contact, but got nil")
					} else {
						assert.Equal(t, tt.expected.IP.Technical.ID, result.IP.Technical.ID, "Technical Contact ID mismatch")
						assert.Equal(t, tt.expected.IP.Technical.Name, result.IP.Technical.Name, "Technical Contact Name mismatch")
						assert.Equal(t, tt.expected.IP.Technical.Phone, result.IP.Technical.Phone, "Technical Contact Phone mismatch")
						assert.Equal(t, tt.expected.IP.Technical.Email, result.IP.Technical.Email, "Technical Contact Email mismatch")
						assert.Equal(t, tt.expected.IP.Technical.ReferralURL, result.IP.Technical.ReferralURL, "Technical Contact ReferralURL mismatch")
					}
				}
			}
		})
	}
}
