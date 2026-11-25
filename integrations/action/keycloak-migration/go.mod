module github.com/casdoor/casdoor-integrations/integrations/action/keycloak-migration

go 1.26.0

require github.com/casdoor/casdoor-integrations/sdk v0.0.0

require (
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/casdoor/casdoor-integrations/sdk => ../../../sdk
