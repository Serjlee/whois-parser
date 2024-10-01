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

import "time"

// WhoisInfo stores domain, IP, or AS WHOIS information.
type WhoisInfo struct {
	Domain         *Domain  `json:"domain,omitempty"`
	Registrar      *Contact `json:"registrar,omitempty"`
	Registrant     *Contact `json:"registrant,omitempty"`
	Administrative *Contact `json:"administrative,omitempty"`
	Technical      *Contact `json:"technical,omitempty"`
	Billing        *Contact `json:"billing,omitempty"`
	IP             *IPInfo  `json:"ip,omitempty"`
	AS             *ASInfo  `json:"as,omitempty"`
}

// Domain stores domain name information.
type Domain struct {
	ID                   string     `json:"id,omitempty"`
	Domain               string     `json:"domain,omitempty"`
	Punycode             string     `json:"punycode,omitempty"`
	Name                 string     `json:"name,omitempty"`
	Extension            string     `json:"extension,omitempty"`
	WhoisServer          string     `json:"whois_server,omitempty"`
	Status               []string   `json:"status,omitempty"`
	NameServers          []string   `json:"name_servers,omitempty"`
	DNSSec               bool       `json:"dnssec,omitempty"`
	CreatedDate          string     `json:"created_date,omitempty"`
	CreatedDateInTime    *time.Time `json:"created_date_in_time,omitempty"`
	UpdatedDate          string     `json:"updated_date,omitempty"`
	UpdatedDateInTime    *time.Time `json:"updated_date_in_time,omitempty"`
	ExpirationDate       string     `json:"expiration_date,omitempty"`
	ExpirationDateInTime *time.Time `json:"expiration_date_in_time,omitempty"`
}

// Contact stores contact information.
type Contact struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	Organization     string `json:"organization,omitempty"`
	Street           string `json:"street,omitempty"`
	City             string `json:"city,omitempty"`
	Province         string `json:"province,omitempty"`
	PostalCode       string `json:"postal_code,omitempty"`
	Country          string `json:"country,omitempty"`
	Phone            string `json:"phone,omitempty"`
	PhoneExt         string `json:"phone_ext,omitempty"`
	Fax              string `json:"fax,omitempty"`
	FaxExt           string `json:"fax_ext,omitempty"`
	Email            string `json:"email,omitempty"`
	ReferralURL      string `json:"referral_url,omitempty"`
	RegistrationDate string `json:"registration_date,omitempty"`
	Updated          string `json:"updated,omitempty"`
	Comment          string `json:"comment,omitempty"`
}

// IPInfo stores IP WHOIS information.
type IPInfo struct {
	Networks  []*Network `json:"networks,omitempty"`
	Abuse     *Contact   `json:"abuse,omitempty"`
	Technical *Contact   `json:"technical,omitempty"`
	Routing   *Contact   `json:"routing,omitempty"`
}

// Network stores IP network information.
type Network struct {
	Range            string   `json:"range,omitempty"`
	CIDR             []string `json:"cidr,omitempty"`
	Name             string   `json:"name,omitempty"`
	Handle           string   `json:"handle,omitempty"`
	Parent           string   `json:"parent,omitempty"`
	Type             string   `json:"type,omitempty"`
	OriginAS         string   `json:"origin_as,omitempty"`
	OrganizationName string   `json:"organization_name,omitempty"` // Add this line
	Organization     *Contact `json:"organization,omitempty"`
	Customer         *Contact `json:"customer,omitempty"`
	RegDate          string   `json:"reg_date,omitempty"`
	Updated          string   `json:"updated,omitempty"`
	Comment          string   `json:"comment,omitempty"`
	Ref              string   `json:"ref,omitempty"`
}

// ASInfo stores AS WHOIS information.
type ASInfo struct {
	Number       string   `json:"number,omitempty"`
	Name         string   `json:"name,omitempty"`
	Handle       string   `json:"handle,omitempty"`
	RegDate      string   `json:"reg_date,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Ref          string   `json:"ref,omitempty"`
	Organization *Contact `json:"organization,omitempty"`
	Routing      *Contact `json:"routing,omitempty"`
	Technical    *Contact `json:"technical,omitempty"`
	Abuse        *Contact `json:"abuse,omitempty"`
}
