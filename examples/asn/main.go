package main

import (
	"fmt"

	"github.com/likexian/whois"

	"github.com/0xDezzy/whois-parser"
)

func main() {
	asNumber := "AS15169" // Google's AS number
	whoisRaw, err := whois.Whois(asNumber)
	if err != nil {
		fmt.Println(err)
		return
	}

	result, err := whoisparser.Parse(whoisRaw)
	if err == nil && result.AS != nil {
		// Print the AS number
		fmt.Println("AS Number:", result.AS.Number)

		// Print the AS name
		fmt.Println("AS Name:", result.AS.Name)

		// Print the organization name
		if result.AS.Organization != nil {
			fmt.Println("Organization:", result.AS.Organization.Organization)
		}

		// Print the technical contact email
		if result.AS.Technical != nil {
			fmt.Println("Technical Contact Email:", result.AS.Technical.Email)
		}
	} else {
		fmt.Println(err)
	}
}
