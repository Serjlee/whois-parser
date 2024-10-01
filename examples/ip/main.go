package main

import (
	"fmt"

	"github.com/likexian/whois"

	"github.com/0xDezzy/whois-parser"
)

func main() {
	ip := "8.8.8.8"
	whoisRaw, err := whois.Whois(ip)
	if err != nil {
		fmt.Println(err)
		return
	}

	result, err := whoisparser.Parse(whoisRaw)
	if err == nil && result.IP != nil && len(result.IP.Networks) > 0 {
		network := result.IP.Networks[0]

		// Print the IP range
		fmt.Println("IP Range:", network.Range)

		// Print the CIDR blocks
		fmt.Println("CIDR Blocks:", network.CIDR)

		// Print the network name
		fmt.Println("Network Name:", network.Name)

		// Print the organization name
		if network.Organization != nil {
			fmt.Println("Organization:", network.Organization.Organization)
		}

		// Print the abuse contact email
		if result.IP.Abuse != nil {
			fmt.Println("Abuse Contact Email:", result.IP.Abuse.Email)
		}
	} else {
		fmt.Println(err)
	}
}
