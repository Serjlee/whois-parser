package whoisparser

import (
	"testing"

	"github.com/likexian/gokit/assert"
)

// TestParseASWhois tests the ParseASWhois function with various inputs.
func TestParseASWhois(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected WhoisInfo
		hasError bool
	}{
		{
			name: "Valid AS WHOIS",
			input: `
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2024, American Registry for Internet Numbers, Ltd.
#

ASNumber:       7132
ASName:         SBIS-AS
ASHandle:       AS7132
RegDate:        1996-09-13
Updated:        2018-07-18    
Ref:            https://rdap.arin.net/registry/autnum/7132


OrgName:        AT&T Corp.
OrgId:          AC-3280
Address:        7277 164th Ave NE
Address:        Attn: IP Management
City:           Redmond
StateProv:      WA
PostalCode:     98052
Country:        US
RegDate:        2018-03-05
Updated:        2024-05-28
Comment:        For policy abuse issues contact abuse@att.net
Comment:        For all subpoena, Internet, court order related matters and emergency requests contact
Comment:        11760 US Highway 1
Comment:        North Palm Beach, FL 33408
Comment:        Main Number: 800-635-6840
Comment:        Fax: 888-938-4715
Ref:            https://rdap.arin.net/registry/entity/AC-3280


OrgAbuseHandle: ABUSE7-ARIN
OrgAbuseName:   abuse
OrgAbusePhone:  +1-919-319-8167 
OrgAbuseEmail:  abuse@att.net
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE7-ARIN

OrgRoutingHandle: ROUTI59-ARIN
OrgRoutingName:   Routing POC
OrgRoutingPhone:  +1-999-999-9999 
OrgRoutingEmail:  routing@cbbtier3.att.net
OrgRoutingRef:    https://rdap.arin.net/registry/entity/ROUTI59-ARIN

OrgTechHandle: ZS44-ARIN
OrgTechName:   IPAdmin-ATT Internet Services
OrgTechPhone:  +1-888-510-5545 
OrgTechEmail:  ipadmin@semail.att.com
OrgTechRef:    https://rdap.arin.net/registry/entity/ZS44-ARIN


#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2024, American Registry for Internet Numbers, Ltd.
#
`,
			expected: WhoisInfo{
				AS: &ASInfo{
					Number:  "7132",
					Name:    "SBIS-AS",
					Handle:  "AS7132",
					RegDate: "1996-09-13",
					Updated: "2018-07-18",
					Ref:     "https://rdap.arin.net/registry/autnum/7132",
					Organization: &Contact{
						Organization:     "AT&T Corp.",
						ID:               "AC-3280",
						Street:           "7277 164th Ave NE\nAttn: IP Management",
						City:             "Redmond",
						Province:         "WA",
						PostalCode:       "98052",
						Country:          "US",
						RegistrationDate: "2018-03-05",
						Updated:          "2024-05-28",
						Comment: `For policy abuse issues contact abuse@att.net
For all subpoena, Internet, court order related matters and emergency requests contact
11760 US Highway 1
North Palm Beach, FL 33408
Main Number: 800-635-6840
Fax: 888-938-4715`,
						ReferralURL: "https://rdap.arin.net/registry/entity/AC-3280",
					},
					Abuse: &Contact{
						ID:          "ABUSE7-ARIN",
						Name:        "abuse",
						Phone:       "+1-919-319-8167",
						Email:       "abuse@att.net",
						ReferralURL: "https://rdap.arin.net/registry/entity/ABUSE7-ARIN",
					},
					Routing: &Contact{
						ID:          "ROUTI59-ARIN",
						Name:        "Routing POC",
						Phone:       "+1-999-999-9999",
						Email:       "routing@cbbtier3.att.net",
						ReferralURL: "https://rdap.arin.net/registry/entity/ROUTI59-ARIN",
					},
					Technical: &Contact{
						ID:          "ZS44-ARIN",
						Name:        "IPAdmin-ATT Internet Services",
						Phone:       "+1-888-510-5545",
						Email:       "ipadmin@semail.att.com",
						ReferralURL: "https://rdap.arin.net/registry/entity/ZS44-ARIN",
					},
				},
			},
			hasError: false,
		},
		{
			name:     "Invalid AS WHOIS",
			input:    "This is not a valid AS WHOIS response",
			expected: WhoisInfo{},
			hasError: true, // Ensure your parser returns an error for invalid inputs
		},
		{
			name: "AS WHOIS with Partial Information",
			input: `
ASNumber:       99999
ASName:         TEST-AS
ASHandle:       AS99999
RegDate:        2021-01-01
Updated:        2022-01-01    
Ref:            https://rdap.arin.net/registry/autnum/99999

OrgName:        Test Organization
OrgId:          TO-5678
Address:        456 Test Blvd
City:           Testville
StateProv:      TS
PostalCode:     54321
Country:        US
RegDate:        2021-01-01
Updated:        2022-01-01
Comment:        This is a test AS.
Ref:            https://rdap.arin.net/registry/entity/TO-5678

OrgAbuseHandle: ABUSE9-ARIN
OrgAbuseName:   abuse-test
OrgAbusePhone:  +1-800-555-1234 
OrgAbuseEmail:  abuse@test.org
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE9-ARIN
`,
			expected: WhoisInfo{
				AS: &ASInfo{
					Number:  "99999",
					Name:    "TEST-AS",
					Handle:  "AS99999",
					RegDate: "2021-01-01",
					Updated: "2022-01-01",
					Ref:     "https://rdap.arin.net/registry/autnum/99999",
					Organization: &Contact{
						Organization:     "Test Organization",
						ID:               "TO-5678",
						Street:           "456 Test Blvd",
						City:             "Testville",
						Province:         "TS",
						PostalCode:       "54321",
						Country:          "US",
						RegistrationDate: "2021-01-01",
						Updated:          "2022-01-01",
						Comment:          "This is a test AS.",
						ReferralURL:      "https://rdap.arin.net/registry/entity/TO-5678",
					},
					Abuse: &Contact{
						ID:          "ABUSE9-ARIN",
						Name:        "abuse-test",
						Phone:       "+1-800-555-1234",
						Email:       "abuse@test.org",
						ReferralURL: "https://rdap.arin.net/registry/entity/ABUSE9-ARIN",
					},
				},
			},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseASWhois(tt.input)
			if tt.hasError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				// Compare AS Basic Information
				assert.Equal(t, tt.expected.AS.Number, result.AS.Number)
				assert.Equal(t, tt.expected.AS.Name, result.AS.Name)
				assert.Equal(t, tt.expected.AS.Handle, result.AS.Handle)
				assert.Equal(t, tt.expected.AS.RegDate, result.AS.RegDate)
				assert.Equal(t, tt.expected.AS.Updated, result.AS.Updated)
				assert.Equal(t, tt.expected.AS.Ref, result.AS.Ref)

				// Compare Organization Information
				if tt.expected.AS.Organization != nil {
					if result.AS.Organization == nil {
						t.Errorf("Expected Organization, but got nil")
					} else {
						assert.Equal(t, tt.expected.AS.Organization.Organization, result.AS.Organization.Organization)
						assert.Equal(t, tt.expected.AS.Organization.ID, result.AS.Organization.ID)
						assert.Equal(t, tt.expected.AS.Organization.Street, result.AS.Organization.Street)
						assert.Equal(t, tt.expected.AS.Organization.City, result.AS.Organization.City)
						assert.Equal(t, tt.expected.AS.Organization.Province, result.AS.Organization.Province)
						assert.Equal(t, tt.expected.AS.Organization.PostalCode, result.AS.Organization.PostalCode)
						assert.Equal(t, tt.expected.AS.Organization.Country, result.AS.Organization.Country)
						assert.Equal(t, tt.expected.AS.Organization.RegistrationDate, result.AS.Organization.RegistrationDate)
						assert.Equal(t, tt.expected.AS.Organization.Updated, result.AS.Organization.Updated)
						assert.Equal(t, tt.expected.AS.Organization.Comment, result.AS.Organization.Comment)
						assert.Equal(t, tt.expected.AS.Organization.ReferralURL, result.AS.Organization.ReferralURL)
					}
				}

				// Compare Abuse Contact Information
				if tt.expected.AS.Abuse != nil {
					if result.AS.Abuse == nil {
						t.Errorf("Expected Abuse contact, but got nil")
					} else {
						assert.Equal(t, tt.expected.AS.Abuse.ID, result.AS.Abuse.ID)
						assert.Equal(t, tt.expected.AS.Abuse.Name, result.AS.Abuse.Name)
						assert.Equal(t, tt.expected.AS.Abuse.Phone, result.AS.Abuse.Phone)
						assert.Equal(t, tt.expected.AS.Abuse.Email, result.AS.Abuse.Email)
						assert.Equal(t, tt.expected.AS.Abuse.ReferralURL, result.AS.Abuse.ReferralURL)
					}
				}

				// Compare Routing Contact Information
				if tt.expected.AS.Routing != nil {
					if result.AS.Routing == nil {
						t.Errorf("Expected Routing contact, but got nil")
					} else {
						assert.Equal(t, tt.expected.AS.Routing.ID, result.AS.Routing.ID)
						assert.Equal(t, tt.expected.AS.Routing.Name, result.AS.Routing.Name)
						assert.Equal(t, tt.expected.AS.Routing.Phone, result.AS.Routing.Phone)
						assert.Equal(t, tt.expected.AS.Routing.Email, result.AS.Routing.Email)
						assert.Equal(t, tt.expected.AS.Routing.ReferralURL, result.AS.Routing.ReferralURL)
					}
				}

				// Compare Technical Contact Information
				if tt.expected.AS.Technical != nil {
					if result.AS.Technical == nil {
						t.Errorf("Expected Technical contact, but got nil")
					} else {
						assert.Equal(t, tt.expected.AS.Technical.ID, result.AS.Technical.ID)
						assert.Equal(t, tt.expected.AS.Technical.Name, result.AS.Technical.Name)
						assert.Equal(t, tt.expected.AS.Technical.Phone, result.AS.Technical.Phone)
						assert.Equal(t, tt.expected.AS.Technical.Email, result.AS.Technical.Email)
						assert.Equal(t, tt.expected.AS.Technical.ReferralURL, result.AS.Technical.ReferralURL)
					}
				}
			}
		})
	}
}

// TestIsASWhois tests the isASWhois function to determine if a WHOIS response is for an AS.
func TestIsASWhois(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid AS WHOIS",
			input:    "ASNumber: 7132\nASName: SBIS-AS",
			expected: true,
		},
		{
			name:     "Valid Domain WHOIS",
			input:    "Domain Name: example.com\nRegistrar: Example Registrar, LLC",
			expected: false,
		},
		{
			name:     "Valid IP WHOIS",
			input:    "NetRange: 192.168.0.0 - 192.168.255.255\nCIDR: 192.168.0.0/16",
			expected: false,
		},
		{
			name:     "AS WHOIS with Additional Fields",
			input:    "ASNumber: 12345\nASName: TEST-AS\nASHandle: AS12345\nOrgName: Test Org",
			expected: true,
		},
		{
			name:     "Empty Input",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isASWhois(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
