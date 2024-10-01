# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.25.0] - 2024-09-30

### Added
- AS (Autonomous System) WHOIS parsing capability
- IP Address WHOIS parsing capability
- New `ASInfo` struct to store AS WHOIS information
- New `IPInfo` struct to store IP WHOIS information
- New `Parse` function to handle all three types of WHOIS parsing
- New `parseASWhois` function to parse AS WHOIS information
- New `parseIPWhois` function to parse IP WHOIS information
- New test cases for AS WHOIS parsing in `as_parser_test.go`
- New test cases for IP WHOIS parsing in `ip_parser_test.go`

### Changed
- Updated version to `1.25.0`
- Updated error handling to support IP and AS WHOIS errors
- Modified project description to include AS and IP WHOIS parsing