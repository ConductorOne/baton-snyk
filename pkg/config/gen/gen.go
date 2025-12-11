// Package main generates configuration code for the Snyk connector.
package main

import (
	"github.com/conductorone/baton-sdk/pkg/config"
	cfg "github.com/conductorone/baton-snyk/pkg/config"
)

func main() {
	config.Generate("snyk", cfg.Config)
}
