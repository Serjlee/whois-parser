# WhoisParser

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://pkg.go.dev/badge/github.com/likexian/whois-parser.svg)](https://pkg.go.dev/github.com/likexian/whois-parser)
[![Go Report Card](https://goreportcard.com/badge/github.com/likexian/whois-parser)](https://goreportcard.com/report/github.com/likexian/whois-parser)
[![Build Status](https://github.com/likexian/whois-parser/actions/workflows/gotest.yaml/badge.svg)](https://github.com/likexian/whois-parser/actions/workflows/gotest.yaml)
[![Code Cover](https://release.likexian.com/whois-parser/coverage.svg)](https://github.com/likexian/whois-parser/actions/workflows/gotest.yaml)

WhoisParser is a simple Go module for domain, IP, and AS whois information parsing.

## Overview

This module parses the provided domain, IP, or AS whois information and returns a readable data struct.

## Verified Extensions

It is supposed to be working with all domain extensions, but [verified extensions](testdata/noterror/README.md) must works, because I have checked them one by one manually.

If there is any problem, please feel free to open a new issue.

## Binary distributions

For binary distributions of whois information query and parsing, please download [whois release tool](https://github.com/likexian/whois/tree/master/cmd/whois).

## Installation

```shell
go get github.com/0xDezzy/whois-parser
```

## Importing

```go
import (
    "github.com/0xDezzy/whois-parser"
)
```

## Documentation

Visit the docs on [GoDoc](https://pkg.go.dev/github.com/0xDezzy/whois-parser)

## Examples

### Domain WHOIS
```go
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
```

### IP WHOIS
```go
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
```

### AS WHOIS
```go
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
```

## Whois information query

Please refer to [whois](https://github.com/likexian/whois)

## License

Copyright 2014-2024 [Li Kexian](https://www.likexian.com/)

Licensed under the Apache License 2.0

## Donation

If this project is helpful, please share it with friends.

If you want to thank me, you can [give me a cup of coffee](https://www.likexian.com/donate/).
