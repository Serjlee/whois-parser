package main

import (
	"fmt"

	"github.com/likexian/whois"

	"github.com/0xDezzy/whois-parser"
)

func main() {
	domain := "example.com"
	whoisRaw, err := whois.Whois(domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	result, err := whoisparser.Parse(whoisRaw)
	if err == nil && result.Domain != nil {
		// Print the domain status
		fmt.Println("Domain Status:", result.Domain.Status)

		// Print the domain created date
		fmt.Println("Created Date:", result.Domain.CreatedDate)

		// Print the domain expiration date
		fmt.Println("Expiration Date:", result.Domain.ExpirationDate)

		// Print the registrar name
		if result.Registrar != nil {
			fmt.Println("Registrar Name:", result.Registrar.Name)
		}

		// Print the registrant name
		if result.Registrant != nil {
			fmt.Println("Registrant Name:", result.Registrant.Name)
		}

		// Print the registrant email address
		if result.Registrant != nil {
			fmt.Println("Registrant Email:", result.Registrant.Email)
		}
	} else {
		fmt.Println(err)
	}
}
