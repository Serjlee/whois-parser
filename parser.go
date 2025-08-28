/*
 * Copyright 2014-2024 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for domain whois information parsing
 * https://www.likexian.com/
 */

package whoisparser

import (
	"errors"
	"regexp"
	"strings"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xslice"
	"golang.org/x/net/idna"
)

// Version returns package version
func Version() string {
	return "1.25.0"
}

// Author returns package author
func Author() string {
	return "[Li Kexian](https://www.likexian.com/)"
}

// License returns package license
func License() string {
	return "Licensed under the Apache License 2.0"
}

// Parse returns parsed whois info for domain, IP, or AS
func Parse(text string) (whoisInfo WhoisInfo, err error) {
	if isASWhois(text) {
		return ParseASWhois(text)
	} else if isIPWhois(text) {
		return ParseIPWhois(text)
	} else {
		return ParseDomainWhois(text)
	}
}

// parseDomainWhois parses domain whois information
func ParseDomainWhois(text string) (whoisInfo WhoisInfo, err error) { //nolint:cyclop
	name, extension := searchDomain(text)
	if name == "" {
		err = getDomainErrorType(text)
		return
	}

	if extension != "" && isExtNotFoundDomain(text, extension) {
		err = ErrNotFoundDomain
		return
	}

	domain := &Domain{}
	registrar := &Contact{}
	registrant := &Contact{}
	administrative := &Contact{}
	technical := &Contact{}
	billing := &Contact{}

	domain.Name, _ = idna.ToASCII(name)
	domain.Extension, _ = idna.ToASCII(extension)

	whoisText, _ := Prepare(text, domain.Extension)
	whoisLines := strings.Split(whoisText, "\n")
	for i := 0; i < len(whoisLines); i++ {
		line := strings.TrimSpace(whoisLines[i])
		if len(line) < 5 || !strings.Contains(line, ":") {
			continue
		}

		fChar := line[:1]
		if assert.IsContains([]string{"-", "*", "%", ">", ";"}, fChar) {
			continue
		}

		if line[len(line)-1:] == ":" {
			i++
			for ; i < len(whoisLines); i++ {
				thisLine := strings.TrimSpace(whoisLines[i])
				if strings.Contains(thisLine, ":") {
					break
				}
				line += thisLine + ","
			}
			line = strings.Trim(line, ",")
			i--
		}

		lines := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(lines[0])
		value := strings.TrimSpace(lines[1])
		value = strings.TrimSpace(strings.Trim(value, ":"))

		if value == "" {
			continue
		}

		keyName := searchKeyName(name)
		switch keyName {
		case "domain_id":
			domain.ID = value
		case "domain_name":
			if domain.Domain == "" {
				if firstSpace := strings.IndexByte(value, ' '); firstSpace > 0 {
					value = value[:firstSpace]
				}
				domain.Domain = strings.ToLower(value)
				domain.Punycode, _ = idna.ToASCII(domain.Domain)
			}
		case "domain_status":
			domain.Status = append(domain.Status, strings.Split(value, ",")...)
		case "domain_dnssec":
			if !domain.DNSSec {
				domain.DNSSec = isDNSSecEnabled(value)
			}
		case "whois_server":
			if domain.WhoisServer == "" {
				domain.WhoisServer = value
			}
		case "name_servers":
			domain.NameServers = append(domain.NameServers, strings.Split(value, ",")...)
		case "created_date":
			if domain.CreatedDate == "" {
				domain.CreatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.CreatedDateInTime = &parsed
				}
			}
		case "updated_date":
			if domain.UpdatedDate == "" {
				domain.UpdatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.UpdatedDateInTime = &parsed
				}
			}
		case "expired_date":
			if domain.ExpirationDate == "" {
				domain.ExpirationDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.ExpirationDateInTime = &parsed
				}
			}
		case "referral_url":
			registrar.ReferralURL = value
		default:
			name = clearKeyName(name)
			if !strings.Contains(name, " ") {
				if name == "registrar" {
					name += " name"
				} else if domain.Extension == "dk" {
					name = "registrant " + name
				} else {
					name += " organization"
				}
			}
			ns := strings.SplitN(name, " ", 2)
			name = strings.TrimSpace("registrant " + ns[1])
			if ns[0] == "registrar" || ns[0] == "registration" {
				parseContact(registrar, name, value)
			} else if ns[0] == "registrant" || ns[0] == "holder" {
				parseContact(registrant, name, value)
			} else if ns[0] == "admin" || ns[0] == "administrative" {
				parseContact(administrative, name, value)
			} else if ns[0] == "tech" || ns[0] == "technical" {
				parseContact(technical, name, value)
			} else if ns[0] == "bill" || ns[0] == "billing" {
				parseContact(billing, name, value)
			}
		}
	}

	domain.NameServers = fixNameServers(domain.NameServers)
	domain.Status = fixDomainStatus(domain.Status)

	domain.NameServers = xslice.Unique(domain.NameServers).([]string)
	domain.Status = xslice.Unique(domain.Status).([]string)

	whoisInfo.Domain = domain
	if *registrar != (Contact{}) {
		whoisInfo.Registrar = registrar
	}

	if *registrant != (Contact{}) {
		whoisInfo.Registrant = registrant
	}

	if *administrative != (Contact{}) {
		whoisInfo.Administrative = administrative
	}

	if *technical != (Contact{}) {
		whoisInfo.Technical = technical
	}

	if *billing != (Contact{}) {
		whoisInfo.Billing = billing
	}

	return
}

// ParseIPWhois parses IP WHOIS information.
func ParseIPWhois(text string) (whoisInfo WhoisInfo, err error) {
	ipInfo := &IPInfo{
		Networks: []*Network{},
	}

	whoisLines := strings.Split(text, "\n")
	var currentNetwork *Network
	currentSection := ""

	fallbackNetworkInfo := &Network{}

	for _, line := range whoisLines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if len(line) < 5 || strings.HasPrefix(line, "#") || !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		// Network-level fields
		case "netrange":
			// Start a new Network section
			currentNetwork = &Network{}
			currentNetwork.Range = value
			ipInfo.Networks = append(ipInfo.Networks, currentNetwork)
			currentSection = "network"
		case "inetnum":
			fallbackNetworkInfo.Range = value
		case "cidr":
			if currentNetwork != nil {
				cidrs := strings.Split(value, ",")
				for _, cidr := range cidrs {
					cidr = strings.TrimSpace(cidr)
					if cidr != "" {
						currentNetwork.CIDR = append(currentNetwork.CIDR, cidr)
					}
				}
			}
			currentSection = "network"
		case "netname":
			if currentNetwork != nil {
				currentNetwork.Name = value
			}
			currentSection = "network"
		case "nethandle":
			if currentNetwork != nil {
				currentNetwork.Handle = value
			}
			currentSection = "network"
		case "parent":
			if currentNetwork != nil {
				currentNetwork.Parent = value
			}
			currentSection = "network"
		case "nettype":
			if currentNetwork != nil {
				currentNetwork.Type = value
			}
			currentSection = "network"
		case "originas":
			if currentNetwork != nil {
				currentNetwork.OriginAS = value
			}
			currentSection = "network"
		case "organization":
			if currentNetwork != nil {
				currentNetwork.OrganizationName = value
				// Do not set currentSection here
			} else {
				fallbackNetworkInfo.OrganizationName = value
			}
		// Organization section starts here
		case "orgname":
			if currentNetwork != nil {
				if currentNetwork.Organization == nil {
					currentNetwork.Organization = &Contact{}
				} else {
					fallbackNetworkInfo.Organization = &Contact{}
					fallbackNetworkInfo.Organization.Name = value
				}
				currentNetwork.Organization.Organization = value
				currentSection = "organization"
			}
		case "orgid":
			if currentNetwork != nil {
				if currentNetwork.Organization == nil {
					currentNetwork.Organization = &Contact{}
				}
				currentNetwork.Organization.ID = value
				currentSection = "organization"
			}
		// Customer section
		case "custname":
			if currentNetwork != nil {
				if currentNetwork.Customer == nil {
					currentNetwork.Customer = &Contact{}
				}
				currentNetwork.Customer.Name = value
				currentSection = "customer"
			}
		// Assign RegDate and Updated based on current section
		case "regdate":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.RegistrationDate = value
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.RegistrationDate = value
					}
				default:
					currentNetwork.RegDate = value
				}
			}
		case "updated":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.Updated = value
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.Updated = value
					}
				default:
					currentNetwork.Updated = value
				}
			}
		case "ref":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.ReferralURL = value
					}
					currentSection = "network" // Reset after organization
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.ReferralURL = value
					}
					currentSection = "network" // Reset after customer
				default:
					currentNetwork.Ref = value
				}
			}
		// Address and contact information
		case "address":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.Street += value + "\n"
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.Street += value + "\n"
					}
				}
			}
		case "city":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.City = value
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.City = value
					}
				}
			}
		case "stateprov", "state":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.Province = value
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.Province = value
					}
				}
			}
		case "postalcode", "postal-code":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.PostalCode = value
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.PostalCode = value
					}
				}
			}
		case "country":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.Country = value
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.Country = value
					}
				}
			} else {
				fallbackNetworkInfo.OrganizationName = value
			}
		case "comment":
			if currentNetwork != nil {
				switch currentSection {
				case "organization":
					if currentNetwork.Organization != nil {
						currentNetwork.Organization.Comment += value + "\n"
					}
				case "customer":
					if currentNetwork.Customer != nil {
						currentNetwork.Customer.Comment += value + "\n"
					}
				default:
					currentNetwork.Comment += value + "\n"
				}
			}
		// Top-level contacts (Abuse, Technical, Routing)
		case "orgabusehandle", "org-abuse-handle":
			// Initialize Abuse contact
			ipInfo.Abuse = &Contact{
				ID: value,
			}
			currentSection = "abuse"
		case "orgabusename", "org-abuse-name":
			if currentSection == "abuse" && ipInfo.Abuse != nil {
				ipInfo.Abuse.Name = value
			}
		case "orgabusephone", "org-abuse-phone":
			if currentSection == "abuse" && ipInfo.Abuse != nil {
				ipInfo.Abuse.Phone = value
			}
		case "orgabuseemail", "org-abuse-email":
			if currentSection == "abuse" && ipInfo.Abuse != nil {
				ipInfo.Abuse.Email = value
			}
		case "orgabuseref", "org-abuse-ref":
			if currentSection == "abuse" && ipInfo.Abuse != nil {
				ipInfo.Abuse.ReferralURL = value
			}
			currentSection = "" // Reset after abuse contact
		case "orgtechhandle", "org-tech-handle":
			// Initialize Technical contact
			ipInfo.Technical = &Contact{
				ID: value,
			}
			currentSection = "technical"
		case "orgtechname", "org-tech-name":
			if currentSection == "technical" && ipInfo.Technical != nil {
				ipInfo.Technical.Name = value
			}
		case "orgtechphone", "org-tech-phone":
			if currentSection == "technical" && ipInfo.Technical != nil {
				ipInfo.Technical.Phone = value
			}
		case "orgtechemail", "org-tech-email":
			if currentSection == "technical" && ipInfo.Technical != nil {
				ipInfo.Technical.Email = value
			}
		case "orgtechref", "org-tech-ref":
			if currentSection == "technical" && ipInfo.Technical != nil {
				ipInfo.Technical.ReferralURL = value
			}
			currentSection = "" // Reset after technical contact
		case "orgroutinghandle", "org-routing-handle":
			// Initialize Routing contact
			ipInfo.Routing = &Contact{
				ID: value,
			}
			currentSection = "routing"
		case "orgroutingname", "org-routing-name":
			if currentSection == "routing" && ipInfo.Routing != nil {
				ipInfo.Routing.Name = value
			}
		case "orgroutingphone", "org-routing-phone":
			if currentSection == "routing" && ipInfo.Routing != nil {
				ipInfo.Routing.Phone = value
			}
		case "orgroutingemail", "org-routing-email":
			if currentSection == "routing" && ipInfo.Routing != nil {
				ipInfo.Routing.Email = value
			}
		case "orgroutingref", "org-routing-ref":
			if currentSection == "routing" && ipInfo.Routing != nil {
				ipInfo.Routing.ReferralURL = value
			}
			currentSection = "" // Reset after routing contact
		// Default case for any additional fields
		default:
			// Handle any additional fields if necessary
		}
	}

	if len(ipInfo.Networks) == 0 && fallbackNetworkInfo.Range != "" {
		ipInfo.Networks = append(ipInfo.Networks, fallbackNetworkInfo)
	}

	// Trim any trailing newlines or spaces
	for _, network := range ipInfo.Networks {
		network.Comment = strings.TrimSpace(network.Comment)
		if network.Organization != nil {
			network.Organization.Street = strings.TrimSpace(network.Organization.Street)
			network.Organization.Comment = strings.TrimSpace(network.Organization.Comment)
		}
		if network.Customer != nil {
			network.Customer.Street = strings.TrimSpace(network.Customer.Street)
			network.Customer.Comment = strings.TrimSpace(network.Customer.Comment)
		}
	}

	whoisInfo.IP = ipInfo
	return
}

// parseASWhois parses AS WHOIS information.
func ParseASWhois(text string) (whoisInfo WhoisInfo, err error) {
	asInfo := &ASInfo{}
	whoisLines := strings.Split(text, "\n")
	currentSection := ""

	// Flags to check mandatory fields
	hasASNumber := false
	hasASHandle := false

	for _, line := range whoisLines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if len(line) < 5 || strings.HasPrefix(line, "#") || !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		// AS Basic Information
		case "asnumber", "as-number", "as number", "aut-num":
			asInfo.Number = strings.TrimPrefix(value, "AS")
			hasASNumber = true
		case "asname", "as-name", "as name":
			asInfo.Name = value
		case "ashandle", "as-handle", "as handle":
			asInfo.Handle = value
			hasASHandle = true
		case "regdate", "registration-date", "created":
			if currentSection == "organization" && asInfo.Organization != nil {
				asInfo.Organization.RegistrationDate = value
			} else {
				asInfo.RegDate = value
			}
		case "updated", "last-modified":
			if currentSection == "organization" && asInfo.Organization != nil {
				asInfo.Organization.Updated = value
			} else {
				asInfo.Updated = value
			}
		case "ref", "reference":
			if currentSection == "organization" && asInfo.Organization != nil {
				asInfo.Organization.ReferralURL = value
			} else {
				asInfo.Ref = value
			}

		// Organization Information
		case "orgname", "org-name", "organization", "owner":
			asInfo.Organization = &Contact{
				Organization: value,
			}
			currentSection = "organization"
		case "orgid", "org-id":
			if asInfo.Organization != nil {
				asInfo.Organization.ID = value
			}
		case "address":
			if asInfo.Organization != nil && currentSection == "organization" {
				asInfo.Organization.Street += value + "\n"
			}
		case "city":
			if asInfo.Organization != nil && currentSection == "organization" {
				asInfo.Organization.City = value
			}
		case "stateprov", "state":
			if asInfo.Organization != nil && currentSection == "organization" {
				asInfo.Organization.Province = value
			}
		case "postalcode", "postal-code":
			if asInfo.Organization != nil && currentSection == "organization" {
				asInfo.Organization.PostalCode = value
			}
		case "country":
			if asInfo.Organization != nil && currentSection == "organization" {
				asInfo.Organization.Country = value
			}

		// Abuse Contact Information
		case "orgabusehandle", "org-abuse-handle":
			asInfo.Abuse = &Contact{
				ID: value,
			}
			currentSection = "abuse"
		case "orgabusename", "org-abuse-name":
			if asInfo.Abuse != nil {
				asInfo.Abuse.Name = value
			}
		case "orgabusephone", "org-abuse-phone":
			if asInfo.Abuse != nil {
				asInfo.Abuse.Phone = value
			}
		case "orgabuseemail", "org-abuse-email":
			if asInfo.Abuse != nil {
				asInfo.Abuse.Email = value
			}
		case "orgabuseref", "org-abuse-ref":
			if asInfo.Abuse != nil {
				asInfo.Abuse.ReferralURL = value
			}

		// Routing Contact Information
		case "orgroutinghandle", "org-routing-handle":
			asInfo.Routing = &Contact{
				ID: value,
			}
			currentSection = "routing"
		case "orgroutingname", "org-routing-name":
			if asInfo.Routing != nil {
				asInfo.Routing.Name = value
			}
		case "orgroutingphone", "org-routing-phone":
			if asInfo.Routing != nil {
				asInfo.Routing.Phone = value
			}
		case "orgroutingemail", "org-routing-email":
			if asInfo.Routing != nil {
				asInfo.Routing.Email = value
			}
		case "orgroutingref", "org-routing-ref":
			if asInfo.Routing != nil {
				asInfo.Routing.ReferralURL = value
			}

		// Technical Contact Information
		case "orgtechhandle", "org-tech-handle":
			asInfo.Technical = &Contact{
				ID: value,
			}
			currentSection = "technical"
		case "orgtechname", "org-tech-name":
			if asInfo.Technical != nil {
				asInfo.Technical.Name = value
			}
		case "orgtechphone", "org-tech-phone":
			if asInfo.Technical != nil {
				asInfo.Technical.Phone = value
			}
		case "orgtechemail", "org-tech-email":
			if asInfo.Technical != nil {
				asInfo.Technical.Email = value
			}
		case "orgtechref", "org-tech-ref":
			if asInfo.Technical != nil {
				asInfo.Technical.ReferralURL = value
			}

		// Comments
		case "comment":
			if asInfo.Organization != nil && currentSection == "organization" {
				asInfo.Organization.Comment += value + "\n"
			}
		}
	}

	// Validate mandatory fields
	if !hasASNumber {
		err = errors.New("ASNumber is missing")
		return
	}
	if !hasASHandle {
		err = errors.New("ASHandle is missing")
		return
	}

	// Trim any trailing newlines or spaces
	if asInfo.Organization != nil {
		asInfo.Organization.Street = strings.TrimSpace(asInfo.Organization.Street)
		asInfo.Organization.Comment = strings.TrimSpace(asInfo.Organization.Comment)
	}
	if asInfo.Routing != nil {
		asInfo.Routing.Street = strings.TrimSpace(asInfo.Routing.Street)
	}
	if asInfo.Technical != nil {
		asInfo.Technical.Street = strings.TrimSpace(asInfo.Technical.Street)
	}
	if asInfo.Abuse != nil {
		asInfo.Abuse.Street = strings.TrimSpace(asInfo.Abuse.Street)
	}

	whoisInfo.AS = asInfo
	return
}

// isIPWhois checks if the WHOIS text is for an IP address
func isIPWhois(text string) bool {
	// Check for typical IP WHOIS keywords
	ipKeywords := []string{"NetRange:", "CIDR:", "inetnum:", "inet6num:"}

	for _, keyword := range ipKeywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

// isASWhois checks if the WHOIS text is for an AS number
func isASWhois(text string) bool {
	return strings.Contains(text, "ASNumber:") || strings.Contains(text, "ASName:") || strings.Contains(text, "aut-num:")
}

// parseContact do parse contact info
func parseContact(contact *Contact, name, value string) {
	switch searchKeyName(name) {
	case "registrant_id":
		contact.ID = value
	case "registrant_name":
		if contact.Name == "" {
			contact.Name = value
		}
	case "registrant_organization":
		if contact.Organization == "" {
			contact.Organization = value
		}
	case "registrant_street":
		if contact.Street == "" {
			contact.Street = value
		} else {
			contact.Street += ", " + value
		}
	case "registrant_city":
		contact.City = value
	case "registrant_state_province":
		contact.Province = value
	case "registrant_postal_code":
		contact.PostalCode = value
	case "registrant_country":
		contact.Country = value
	case "registrant_phone":
		contact.Phone = value
	case "registrant_phone_ext":
		contact.PhoneExt = value
	case "registrant_fax":
		contact.Fax = value
	case "registrant_fax_ext":
		contact.FaxExt = value
	case "registrant_email":
		contact.Email = strings.ToLower(value)
	}
}

var searchDomainRx1 = regexp.MustCompile(`(?i)\[?domain\:?(\s*\_?name)?\]?[\s\.]*\:?` +
	`\s*([^\s\,\;\@\(\)]+)\.([^\s\,\;\(\)\.]{2,})`)
var searchDomainRx2 = regexp.MustCompile(`(?i)\[?domain\:?(\s*\_?name)?\]?[\s\.]*\:?` +
	`\s*([^\s\,\;\@\(\)\.]{2,})\n`)

// searchDomain finds domain name and extension from whois information
func searchDomain(text string) (name, extension string) {
	m := searchDomainRx1.FindStringSubmatch(text)
	if len(m) > 0 {
		name = strings.TrimPrefix(strings.TrimSpace(m[2]), "\"")
		extension = strings.TrimSuffix(strings.TrimSpace(m[3]), "\"")
	}

	if name == "" {
		m := searchDomainRx2.FindStringSubmatch(text)
		if len(m) > 0 {
			name = strings.TrimSpace(m[2])
			extension = ""
		}
	}

	if name != "" {
		name = strings.ToLower(name)
		extension = strings.ToLower(extension)
	}

	return
}
