// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Keycloak migration reads the realm export of Keycloak (kc.sh export) for a Casdoor migration: the signing keys,
// groups, OpenID Connect clients, users with their password hashes, TOTP and identity provider links, and the realm
// and client roles. It runs on the uploaded files only and sends no requests.
package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casdoor/casdoor-integrations/sdk"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const usersPerPage = 500

// the clients and roles every realm has, which Casdoor has its own of
var builtInClients = map[string]bool{
	"account":                true,
	"account-console":        true,
	"admin-cli":              true,
	"broker":                 true,
	"realm-management":       true,
	"security-admin-console": true,
}

var builtInRealmRoles = map[string]bool{
	"offline_access":    true,
	"uma_authorization": true,
}

// the identity provider aliases that are a field of the Casdoor user, which its sign-in looks the user up by
var linkFields = map[string]string{
	"github":    "github",
	"google":    "google",
	"facebook":  "facebook",
	"gitlab":    "gitlab",
	"linkedin":  "linkedin",
	"apple":     "apple",
	"twitter":   "twitter",
	"microsoft": "azuread",
	"bitbucket": "bitbucket",
	"discord":   "discord",
	"instagram": "instagram",
	"paypal":    "paypal",
	"slack":     "slack",
	"gitea":     "gitea",
	"okta":      "okta",
}

var namePattern = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

type importer struct{}

type realm struct {
	Realm        string                       `json:"realm"`
	Users        []*kcUser                    `json:"users"`
	Groups       []*kcGroup                   `json:"groups"`
	Clients      []*kcClient                  `json:"clients"`
	Roles        *kcRoles                     `json:"roles"`
	Components   map[string][]*kcComponent    `json:"components"`
	Providers    []map[string]interface{}     `json:"identityProviders"`
	DefaultRole  *kcRole                      `json:"defaultRole"`
	Registration bool                         `json:"registrationAllowed"`
	Organization []map[string]json.RawMessage `json:"organizations"`
}

type kcRoles struct {
	Realm  []*kcRole            `json:"realm"`
	Client map[string][]*kcRole `json:"client"`
}

type kcRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
	Composites  *struct {
		Realm  []string            `json:"realm"`
		Client map[string][]string `json:"client"`
	} `json:"composites"`
}

type kcGroup struct {
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	Attributes  map[string][]string `json:"attributes"`
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
	SubGroups   []*kcGroup          `json:"subGroups"`
}

type kcClient struct {
	ClientId                  string            `json:"clientId"`
	Name                      string            `json:"name"`
	Description               string            `json:"description"`
	RootUrl                   string            `json:"rootUrl"`
	BaseUrl                   string            `json:"baseUrl"`
	Secret                    string            `json:"secret"`
	RedirectUris              []string          `json:"redirectUris"`
	Protocol                  string            `json:"protocol"`
	PublicClient              bool              `json:"publicClient"`
	BearerOnly                bool              `json:"bearerOnly"`
	Enabled                   *bool             `json:"enabled"`
	StandardFlowEnabled       *bool             `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	Attributes                map[string]string `json:"attributes"`
}

type kcComponent struct {
	Name       string              `json:"name"`
	ProviderId string              `json:"providerId"`
	Config     map[string][]string `json:"config"`
}

type kcCredential struct {
	Type           string `json:"type"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
}

type kcUser struct {
	Id                  string              `json:"id"`
	CreatedTimestamp    int64               `json:"createdTimestamp"`
	Username            string              `json:"username"`
	Enabled             bool                `json:"enabled"`
	EmailVerified       bool                `json:"emailVerified"`
	FirstName           string              `json:"firstName"`
	LastName            string              `json:"lastName"`
	Email               string              `json:"email"`
	Attributes          map[string][]string `json:"attributes"`
	Credentials         []*kcCredential     `json:"credentials"`
	RequiredActions     []string            `json:"requiredActions"`
	FederationLink      string              `json:"federationLink"`
	RealmRoles          []string            `json:"realmRoles"`
	ClientRoles         map[string][]string `json:"clientRoles"`
	Groups              []string            `json:"groups"`
	FederatedIdentities []*struct {
		IdentityProvider string `json:"identityProvider"`
		UserId           string `json:"userId"`
	} `json:"federatedIdentities"`
}

type metadata struct {
	// the realm to import when the files have several, such as master and the realm of the applications
	Realm string `json:"realm"`
}

// export is the realm read from the files, with the names its objects get in Casdoor
type export struct {
	realm       *realm
	users       []*kcUser
	groupNames  map[string]string
	groups      []*kcGroup
	parents     map[*kcGroup]*kcGroup
	clientNames map[string]string
	cert        string
	warnings    []string
}

func getMetadata(config *sdk.Config) (*metadata, error) {
	m := &metadata{}
	if strings.TrimSpace(config.Metadata) == "" {
		return m, nil
	}
	err := json.Unmarshal([]byte(config.Metadata), m)
	if err != nil {
		return nil, fmt.Errorf("the metadata is not valid JSON: %w", err)
	}
	return m, nil
}

// readRealms reads a realm file, a file with several realms, or a users file of the export ({"realm": ..., "users": [...]})
func readRealms(file *sdk.ImportFile) ([]*realm, error) {
	data := []byte(strings.TrimSpace(string(file.Data)))
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", file.Name)
	}
	if data[0] == '[' {
		realms := []*realm{}
		err := json.Unmarshal(data, &realms)
		if err != nil {
			return nil, fmt.Errorf("%s is not a Keycloak export: %w", file.Name, err)
		}
		return realms, nil
	}
	r := &realm{}
	err := json.Unmarshal(data, r)
	if err != nil {
		return nil, fmt.Errorf("%s is not a Keycloak export: %w", file.Name, err)
	}
	return []*realm{r}, nil
}

func readExport(config *sdk.Config, files []*sdk.ImportFile) (*export, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("upload the realm export of Keycloak, made with kc.sh export")
	}
	m, err := getMetadata(config)
	if err != nil {
		return nil, err
	}

	realms := map[string]*realm{}
	names := []string{}
	for _, file := range files {
		list, err := readRealms(file)
		if err != nil {
			return nil, err
		}
		for _, r := range list {
			if r.Realm == "" {
				return nil, fmt.Errorf("%s is not a Keycloak export: it names no realm", file.Name)
			}
			existing, ok := realms[r.Realm]
			if !ok {
				realms[r.Realm] = r
				names = append(names, r.Realm)
				continue
			}
			// the users of a realm may be split into files of their own
			existing.Users = append(existing.Users, r.Users...)
			if existing.Clients == nil && r.Clients != nil {
				users := existing.Users
				*existing = *r
				existing.Users = users
			}
		}
	}

	name := m.Realm
	if name == "" {
		candidates := []string{}
		for _, realmName := range names {
			if realmName != "master" {
				candidates = append(candidates, realmName)
			}
		}
		if len(candidates) == 0 && len(names) == 1 {
			candidates = names
		}
		if len(candidates) != 1 {
			return nil, fmt.Errorf("the files have the realms %s, set the one to import in the metadata, such as {\"realm\": \"%s\"}", strings.Join(names, ", "), names[0])
		}
		name = candidates[0]
	}
	r, ok := realms[name]
	if !ok {
		return nil, fmt.Errorf("the files have no realm: %s, they have %s", name, strings.Join(names, ", "))
	}

	e := &export{realm: r, users: r.Users, groupNames: map[string]string{}, parents: map[*kcGroup]*kcGroup{}, clientNames: map[string]string{}}
	e.nameGroups()
	e.nameClients()
	e.cert, _ = e.getSigningKey()
	e.collectWarnings()
	return e, nil
}

func (e *export) nameGroups() {
	var walk func(groups []*kcGroup, parent *kcGroup)
	walk = func(groups []*kcGroup, parent *kcGroup) {
		for _, group := range groups {
			if group.Path == "" {
				if parent == nil {
					group.Path = "/" + group.Name
				} else {
					group.Path = parent.Path + "/" + group.Name
				}
			}
			e.groups = append(e.groups, group)
			e.parents[group] = parent
			walk(group.SubGroups, group)
		}
	}
	walk(e.realm.Groups, nil)

	// a name used in two places of the tree is told apart by its path
	counts := map[string]int{}
	for _, group := range e.groups {
		counts[sanitize(group.Name)]++
	}
	for _, group := range e.groups {
		name := sanitize(group.Name)
		if counts[name] > 1 {
			name = sanitize(strings.ReplaceAll(strings.Trim(group.Path, "/"), "/", "-"))
		}
		e.groupNames[group.Path] = name
	}
}

func (e *export) isImportedClient(client *kcClient) bool {
	if builtInClients[client.ClientId] || strings.HasSuffix(client.ClientId, "-realm") {
		return false
	}
	return client.Protocol == "" || client.Protocol == "openid-connect"
}

func (e *export) nameClients() {
	for _, client := range e.realm.Clients {
		if e.isImportedClient(client) {
			e.clientNames[client.ClientId] = sanitize(client.ClientId)
		}
	}
}

func (e *export) collectWarnings() {
	add := func(format string, args ...interface{}) {
		e.warnings = append(e.warnings, fmt.Sprintf(format, args...))
	}

	skipped := []string{}
	masked := []string{}
	bearerOnly := []string{}
	for _, client := range e.realm.Clients {
		if builtInClients[client.ClientId] || strings.HasSuffix(client.ClientId, "-realm") {
			continue
		}
		if !e.isImportedClient(client) {
			skipped = append(skipped, client.ClientId)
		} else if client.BearerOnly {
			bearerOnly = append(bearerOnly, client.ClientId)
		} else if strings.Trim(client.Secret, "*") == "" && client.Secret != "" {
			masked = append(masked, client.ClientId)
		}
	}
	if len(skipped) > 0 {
		add("Casdoor imports the OpenID Connect clients only, these clients of other protocols are not imported: %s", strings.Join(skipped, ", "))
	}
	if len(bearerOnly) > 0 {
		add("These bearer-only clients are imported as applications that only check tokens: %s", strings.Join(bearerOnly, ", "))
	}
	if len(masked) > 0 {
		add("The export hides the secrets of %s, so Casdoor gives them new ones. Use kc.sh export rather than the partial export of the admin console to keep them", strings.Join(masked, ", "))
	}
	if len(e.realm.Providers) > 0 {
		aliases := []string{}
		for _, provider := range e.realm.Providers {
			if alias, ok := provider["alias"].(string); ok {
				aliases = append(aliases, alias)
			}
		}
		add("Add the identity providers %s to Casdoor as providers of the applications, their users keep the links to them", strings.Join(aliases, ", "))
	}
	if len(e.realm.Organization) > 0 {
		add("The %d Keycloak organizations are not imported, the groups and users are", len(e.realm.Organization))
	}

	federated, required, webauthn := 0, 0, 0
	for _, user := range e.users {
		if user.FederationLink != "" {
			federated++
		}
		if len(user.RequiredActions) > 0 {
			required++
		}
		for _, credential := range user.Credentials {
			if strings.HasPrefix(credential.Type, "webauthn") {
				webauthn++
				break
			}
		}
	}
	if len(e.users) == 0 {
		add("The files have no users, export them with kc.sh export --users realm_file or different_files")
	}
	if federated > 0 {
		add("%d users come from a user federation such as LDAP, the export has no passwords of them: add the LDAP server to Casdoor or have them reset their passwords", federated)
	}
	if required > 0 {
		add("%d users have required actions in Keycloak, such as verifying the email or updating the password, which are not imported", required)
	}
	if webauthn > 0 {
		add("%d users have passkeys or security keys, which are bound to the Keycloak domain and have to be registered again", webauthn)
	}
}

func sanitize(name string) string {
	name = strings.Trim(namePattern.ReplaceAllString(strings.TrimSpace(name), "-"), "-")
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

func getTime(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (e *export) listCerts() ([]interface{}, error) {
	items := []interface{}{}
	names := map[string]int{}
	for _, key := range e.getRsaKeys() {
		privateKey, certificate := first(key.Config["privateKey"]), first(key.Config["certificate"])
		if privateKey == "" || certificate == "" {
			continue
		}
		keyId, err := getKeyId(key, certificate)
		if err != nil {
			return nil, err
		}
		algorithm := first(key.Config["algorithm"])
		if algorithm == "" {
			algorithm = "RS256"
		}
		bitSize, _ := strconv.Atoi(first(key.Config["keySize"]))
		if bitSize == 0 {
			bitSize = 2048
		}

		name := getCertName(key)
		names[name]++
		if names[name] > 1 {
			name = fmt.Sprintf("%s-%d", name, names[name])
		}
		items = append(items, map[string]interface{}{
			"name":            name,
			"displayName":     fmt.Sprintf("%s (Keycloak %s)", key.Name, e.realm.Realm),
			"scope":           "JWT",
			"type":            "x509",
			"cryptoAlgorithm": algorithm,
			"bitSize":         bitSize,
			"keyId":           keyId,
			"certificate":     getPem("CERTIFICATE", certificate),
			"privateKey":      getPrivateKeyPem(privateKey),
		})
	}
	return items, nil
}

func getCertName(key *kcComponent) string {
	name := sanitize(key.Name)
	if name == "" {
		name = sanitize(key.ProviderId)
	}
	return "keycloak-" + name
}

// getRsaKeys returns the RSA signing keys of the realm with the active one of the highest priority first
func (e *export) getRsaKeys() []*kcComponent {
	keys := []*kcComponent{}
	for _, key := range e.realm.Components["org.keycloak.keys.KeyProvider"] {
		if key.ProviderId != "rsa-generated" && key.ProviderId != "rsa" {
			continue
		}
		if use := first(key.Config["keyUse"]); use != "" && !strings.EqualFold(use, "sig") {
			continue
		}
		keys = append(keys, key)
	}
	priority := func(key *kcComponent) int {
		if first(key.Config["active"]) == "false" || first(key.Config["enabled"]) == "false" {
			return -1 << 30
		}
		p, _ := strconv.Atoi(first(key.Config["priority"]))
		return p
	}
	sort.SliceStable(keys, func(i, j int) bool { return priority(keys[i]) > priority(keys[j]) })
	return keys
}

func (e *export) getSigningKey() (string, bool) {
	keys := e.getRsaKeys()
	if len(keys) == 0 || first(keys[0].Config["privateKey"]) == "" {
		return "", false
	}
	return getCertName(keys[0]), true
}

func getPem(kind string, body string) string {
	body = strings.Join(strings.Fields(body), "")
	lines := []string{"-----BEGIN " + kind + "-----"}
	for len(body) > 64 {
		lines = append(lines, body[:64])
		body = body[64:]
	}
	lines = append(lines, body, "-----END "+kind+"-----", "")
	return strings.Join(lines, "\n")
}

// getPrivateKeyPem tells PKCS #1, which Keycloak writes for its generated keys, from PKCS #8: after the version, a
// PKCS #8 key has the algorithm sequence and a PKCS #1 key the modulus integer
func getPrivateKeyPem(body string) string {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err == nil {
		var key struct {
			Version   int
			Algorithm asn1.RawValue
		}
		if _, err = asn1.Unmarshal(der, &key); err == nil && key.Algorithm.Tag == asn1.TagInteger {
			return getPem("RSA PRIVATE KEY", body)
		}
	}
	return getPem("PRIVATE KEY", body)
}

// getKeyId is the kid of Keycloak's tokens: the one set on the key, or base64url(SHA-256) of its public key info
func getKeyId(key *kcComponent, certificate string) (string, error) {
	if kid := first(key.Config["kid"]); kid != "" {
		return kid, nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(certificate), ""))
	if err != nil {
		return "", fmt.Errorf("the certificate of the key: %s is not base64: %w", key.Name, err)
	}

	var cert asn1.RawValue
	if _, err = asn1.Unmarshal(der, &cert); err != nil {
		return "", fmt.Errorf("the certificate of the key: %s is not valid: %w", key.Name, err)
	}
	var tbs asn1.RawValue
	if _, err = asn1.Unmarshal(cert.Bytes, &tbs); err != nil {
		return "", fmt.Errorf("the certificate of the key: %s is not valid: %w", key.Name, err)
	}
	fields := []asn1.RawValue{}
	rest := tbs.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return "", fmt.Errorf("the certificate of the key: %s is not valid: %w", key.Name, err)
		}
		fields = append(fields, field)
	}
	// version (optional), serial number, signature, issuer, validity, subject, subject public key info
	index := 5
	if len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		index = 6
	}
	if len(fields) <= index {
		return "", fmt.Errorf("the certificate of the key: %s has no public key", key.Name)
	}
	sum := sha256.Sum256(fields[index].FullBytes)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (e *export) listGroups() []interface{} {
	items := []interface{}{}
	for _, group := range e.groups {
		parentId := ""
		if parent := e.parents[group]; parent != nil {
			parentId = e.groupNames[parent.Path]
		}
		properties := map[string]string{}
		for key, values := range group.Attributes {
			properties[key] = strings.Join(values, ",")
		}
		items = append(items, map[string]interface{}{
			"name":        e.groupNames[group.Path],
			"displayName": group.Name,
			"parentId":    parentId,
			"type":        "Virtual",
			"properties":  properties,
		})
	}
	return items
}

// getRedirectUri turns Keycloak's wildcard and relative redirect URIs into the URIs and patterns Casdoor matches
func getRedirectUri(uri string, rootUrl string) string {
	if strings.HasPrefix(uri, "/") && rootUrl != "" {
		uri = strings.TrimRight(rootUrl, "/") + uri
	}
	if !strings.Contains(uri, "*") {
		return uri
	}
	return strings.ReplaceAll(regexp.QuoteMeta(uri), `\*`, ".*")
}

func (e *export) listApplications() []interface{} {
	items := []interface{}{}
	for _, client := range e.realm.Clients {
		name, ok := e.clientNames[client.ClientId]
		if !ok {
			continue
		}

		grantTypes := []string{}
		if !client.BearerOnly {
			if client.StandardFlowEnabled == nil || *client.StandardFlowEnabled {
				grantTypes = append(grantTypes, "authorization_code", "refresh_token")
			}
			if client.ImplicitFlowEnabled {
				grantTypes = append(grantTypes, "token", "id_token")
			}
			if client.DirectAccessGrantsEnabled {
				grantTypes = append(grantTypes, "password")
			}
		}
		if client.ServiceAccountsEnabled {
			grantTypes = append(grantTypes, "client_credentials")
		}

		redirectUris := []string{}
		for _, uri := range client.RedirectUris {
			if uri = getRedirectUri(uri, client.RootUrl); uri != "" {
				redirectUris = append(redirectUris, uri)
			}
		}

		displayName := client.Name
		if displayName == "" || strings.HasPrefix(displayName, "${") {
			displayName = client.ClientId
		}
		homepage := client.BaseUrl
		if strings.HasPrefix(homepage, "/") || homepage == "" {
			homepage = strings.TrimRight(client.RootUrl, "/") + homepage
		}

		item := map[string]interface{}{
			"name":         name,
			"displayName":  displayName,
			"description":  client.Description,
			"homepageUrl":  homepage,
			"clientId":     client.ClientId,
			"redirectUris": redirectUris,
			"grantTypes":   grantTypes,
			"tokenFormat":  "JWT-Standard",
			"cert":         e.cert,
			"enableSignUp": e.realm.Registration,
		}
		if !client.PublicClient && strings.Trim(client.Secret, "*") != "" {
			item["clientSecret"] = client.Secret
		}
		items = append(items, item)
	}
	return items
}

// getPassword turns a Keycloak password credential into a Casdoor hash: Casdoor checks Keycloak's old default
// itself, the other algorithms and parameters are checked by VerifyImportedPassword
func getPassword(credential *kcCredential) (string, string, string, error) {
	secret := struct {
		Value string `json:"value"`
		Salt  string `json:"salt"`
	}{}
	data := struct {
		HashIterations       int                 `json:"hashIterations"`
		Algorithm            string              `json:"algorithm"`
		AdditionalParameters map[string][]string `json:"additionalParameters"`
	}{}
	if err := json.Unmarshal([]byte(credential.SecretData), &secret); err != nil {
		return "", "", "", err
	}
	if err := json.Unmarshal([]byte(credential.CredentialData), &data); err != nil {
		return "", "", "", err
	}
	hashBytes, err := base64.StdEncoding.DecodeString(secret.Value)
	if err != nil {
		return "", "", "", fmt.Errorf("the password hash is not base64")
	}

	switch data.Algorithm {
	case "pbkdf2-sha256", "pbkdf2-sha512", "pbkdf2":
		if data.Algorithm == "pbkdf2-sha256" && data.HashIterations == 27500 && len(hashBytes) == 64 {
			return secret.Value, secret.Salt, "pbkdf2-salt", nil
		}
		return fmt.Sprintf("%s$%d$%s", data.Algorithm, data.HashIterations, secret.Value), secret.Salt, "plugin", nil
	case "argon2":
		params := data.AdditionalParameters
		kind := first(params["type"])
		if kind == "" {
			kind = "id"
		}
		if kind != "id" && kind != "i" {
			return "", "", "", fmt.Errorf("argon2%s passwords are not supported", kind)
		}
		if version := first(params["version"]); version != "" && version != "1.3" {
			return "", "", "", fmt.Errorf("argon2 version %s passwords are not supported", version)
		}
		memory, parallelism := first(params["memory"]), first(params["parallelism"])
		if memory == "" {
			memory = "7168"
		}
		if parallelism == "" {
			parallelism = "1"
		}
		return fmt.Sprintf("argon2%s$%d$%s$%s$%s", kind, data.HashIterations, memory, parallelism, secret.Value), secret.Salt, "plugin", nil
	}
	return "", "", "", fmt.Errorf("the password algorithm %s is not supported", data.Algorithm)
}

// getTotpSecret turns a Keycloak TOTP credential into Casdoor's secret: Keycloak keeps the secret as text and shows
// the base32 of its bytes to the authenticator apps
func getTotpSecret(credential *kcCredential) (string, error) {
	secret := struct {
		Value string `json:"value"`
	}{}
	data := struct {
		SubType   string `json:"subType"`
		Digits    int    `json:"digits"`
		Period    int    `json:"period"`
		Algorithm string `json:"algorithm"`
	}{}
	if err := json.Unmarshal([]byte(credential.SecretData), &secret); err != nil {
		return "", err
	}
	if err := json.Unmarshal([]byte(credential.CredentialData), &data); err != nil {
		return "", err
	}
	if data.SubType != "" && data.SubType != "totp" {
		return "", fmt.Errorf("%s one-time passwords are not supported", data.SubType)
	}
	if data.Algorithm != "" && data.Algorithm != "HmacSHA1" {
		return "", fmt.Errorf("%s one-time passwords are not supported", data.Algorithm)
	}
	res := strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(secret.Value)), "=")
	query := []string{}
	if data.Period != 0 && data.Period != 30 {
		query = append(query, fmt.Sprintf("period=%d", data.Period))
	}
	if data.Digits == 8 {
		query = append(query, "digits=8")
	} else if data.Digits != 0 && data.Digits != 6 {
		return "", fmt.Errorf("%d-digit one-time passwords are not supported", data.Digits)
	}
	if len(query) > 0 {
		res += "?" + strings.Join(query, "&")
	}
	return res, nil
}

func (e *export) getUser(user *kcUser, warnings map[string]int) map[string]interface{} {
	displayName := strings.TrimSpace(user.FirstName + " " + user.LastName)
	if displayName == "" {
		displayName = user.Username
	}
	properties := map[string]string{}
	for key, values := range user.Attributes {
		properties[key] = strings.Join(values, ",")
	}
	groups := []string{}
	for _, path := range user.Groups {
		if name, ok := e.groupNames[path]; ok {
			groups = append(groups, name)
		}
	}

	item := map[string]interface{}{
		"id":            user.Id,
		"name":          user.Username,
		"displayName":   displayName,
		"firstName":     user.FirstName,
		"lastName":      user.LastName,
		"email":         user.Email,
		"emailVerified": user.EmailVerified,
		"isForbidden":   !user.Enabled,
		"createdTime":   getTime(user.CreatedTimestamp),
		"properties":    properties,
		"groups":        groups,
	}

	for _, credential := range user.Credentials {
		switch credential.Type {
		case "password":
			if _, ok := item["password"]; ok {
				continue
			}
			password, salt, passwordType, err := getPassword(credential)
			if err != nil {
				warnings[fmt.Sprintf("%%d users have passwords that are not imported: %s, they have to reset them", err.Error())]++
				continue
			}
			item["password"], item["passwordSalt"], item["passwordType"] = password, salt, passwordType
		case "otp":
			if _, ok := item["totpSecret"]; ok {
				continue
			}
			secret, err := getTotpSecret(credential)
			if err != nil {
				warnings[fmt.Sprintf("%%d users have authenticator apps that are not imported: %s, they have to set them up again", err.Error())]++
				continue
			}
			item["totpSecret"], item["preferredMfaType"] = secret, "app"
		}
	}

	for _, identity := range user.FederatedIdentities {
		field, ok := linkFields[strings.ToLower(identity.IdentityProvider)]
		if ok {
			item[field] = identity.UserId
		} else {
			properties[fmt.Sprintf("oauth_%s_id", identity.IdentityProvider)] = identity.UserId
		}
	}
	return item
}

func (e *export) listUsers(cursor string) ([]interface{}, string, []string, error) {
	start := 0
	if cursor != "" {
		var err error
		start, err = strconv.Atoi(cursor)
		if err != nil || start < 0 {
			return nil, "", nil, fmt.Errorf("invalid cursor: %s", cursor)
		}
	}
	if start >= len(e.users) {
		return []interface{}{}, "", nil, nil
	}
	end := start + usersPerPage
	if end > len(e.users) {
		end = len(e.users)
	}

	warningCounts := map[string]int{}
	items := []interface{}{}
	for _, user := range e.users[start:end] {
		items = append(items, e.getUser(user, warningCounts))
	}
	warnings := []string{}
	for format, count := range warningCounts {
		warnings = append(warnings, fmt.Sprintf(format, count))
	}

	next := ""
	if end < len(e.users) {
		next = strconv.Itoa(end)
	}
	return items, next, warnings, nil
}

func (e *export) getRoleName(client string, role string) string {
	if client == "" {
		return sanitize(role)
	}
	return sanitize(e.clientNames[client] + "-" + role)
}

func (e *export) listRoles() []interface{} {
	if e.realm.Roles == nil {
		return []interface{}{}
	}

	type roleItem struct {
		name        string
		displayName string
		description string
		users       []string
		groups      []string
		roles       []string
	}
	roles := map[string]*roleItem{}
	order := []string{}
	isDefault := func(name string) bool {
		return builtInRealmRoles[name] || name == "default-roles-"+strings.ToLower(e.realm.Realm) || (e.realm.DefaultRole != nil && name == e.realm.DefaultRole.Name)
	}
	addRole := func(client string, role *kcRole) {
		name := e.getRoleName(client, role.Name)
		if name == "" {
			return
		}
		description := role.Description
		if client != "" && description == "" {
			description = fmt.Sprintf("The role %s of the client %s", role.Name, client)
		}
		item := &roleItem{name: name, displayName: role.Name, description: description}
		if role.Composites != nil {
			for _, sub := range role.Composites.Realm {
				if !isDefault(sub) {
					item.roles = append(item.roles, e.getRoleName("", sub))
				}
			}
			for subClient, subs := range role.Composites.Client {
				if _, ok := e.clientNames[subClient]; ok {
					for _, sub := range subs {
						item.roles = append(item.roles, e.getRoleName(subClient, sub))
					}
				}
			}
		}
		roles[client+"\x00"+role.Name] = item
		order = append(order, client+"\x00"+role.Name)
	}

	for _, role := range e.realm.Roles.Realm {
		if !isDefault(role.Name) {
			addRole("", role)
		}
	}
	clients := []string{}
	for client := range e.realm.Roles.Client {
		clients = append(clients, client)
	}
	sort.Strings(clients)
	for _, client := range clients {
		if _, ok := e.clientNames[client]; !ok {
			continue
		}
		for _, role := range e.realm.Roles.Client[client] {
			addRole(client, role)
		}
	}

	for _, user := range e.users {
		for _, role := range user.RealmRoles {
			if item, ok := roles["\x00"+role]; ok {
				item.users = append(item.users, user.Username)
			}
		}
		for client, list := range user.ClientRoles {
			for _, role := range list {
				if item, ok := roles[client+"\x00"+role]; ok {
					item.users = append(item.users, user.Username)
				}
			}
		}
	}
	for _, group := range e.groups {
		name := e.groupNames[group.Path]
		for _, role := range group.RealmRoles {
			if item, ok := roles["\x00"+role]; ok {
				item.groups = append(item.groups, name)
			}
		}
		for client, list := range group.ClientRoles {
			for _, role := range list {
				if item, ok := roles[client+"\x00"+role]; ok {
					item.groups = append(item.groups, name)
				}
			}
		}
	}

	items := []interface{}{}
	for _, key := range order {
		item := roles[key]
		items = append(items, map[string]interface{}{
			"name":        item.name,
			"displayName": item.displayName,
			"description": item.description,
			"users":       nonNil(item.users),
			"groups":      nonNil(item.groups),
			"roles":       nonNil(item.roles),
			"isEnabled":   true,
		})
	}
	return items
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func (importer) List(config *sdk.Config, req *sdk.ImportListReq) (*sdk.ImportListResp, error) {
	e, err := readExport(config, req.Files)
	if err != nil {
		return nil, err
	}

	resp := &sdk.ImportListResp{Items: []interface{}{}}
	switch req.Kind {
	case "certs":
		resp.Items, err = e.listCerts()
		resp.Warnings = e.warnings
	case "groups":
		resp.Items = e.listGroups()
	case "applications":
		resp.Items = e.listApplications()
	case "users":
		resp.Items, resp.Cursor, resp.Warnings, err = e.listUsers(req.Cursor)
	case "roles":
		resp.Items = e.listRoles()
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (importer) Test(config *sdk.Config, files []*sdk.ImportFile) error {
	_, err := readExport(config, files)
	return err
}

func (importer) VerifyImportedPassword(req *sdk.VerifyImportedPasswordReq) (bool, error) {
	parts := strings.Split(req.Hash, "$")
	salt, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil {
		return false, fmt.Errorf("the salt is not base64")
	}

	var expected, actual []byte
	switch {
	case len(parts) == 3 && strings.HasPrefix(parts[0], "pbkdf2"):
		iterations, err := strconv.Atoi(parts[1])
		if err != nil || iterations <= 0 {
			return false, fmt.Errorf("invalid iterations: %s", parts[1])
		}
		expected, err = base64.StdEncoding.DecodeString(parts[2])
		if err != nil || len(expected) == 0 {
			return false, fmt.Errorf("the hash is not base64")
		}
		var h func() hash.Hash
		switch parts[0] {
		case "pbkdf2-sha256":
			h = sha256.New
		case "pbkdf2-sha512":
			h = sha512.New
		default:
			h = sha1.New
		}
		actual = pbkdf2.Key([]byte(req.Password), salt, iterations, len(expected), h)
	case len(parts) == 5 && (parts[0] == "argon2id" || parts[0] == "argon2i"):
		values := make([]int, 3)
		for i := range values {
			values[i], err = strconv.Atoi(parts[i+1])
			if err != nil || values[i] <= 0 {
				return false, fmt.Errorf("invalid argon2 parameter: %s", parts[i+1])
			}
		}
		expected, err = base64.StdEncoding.DecodeString(parts[4])
		if err != nil || len(expected) == 0 {
			return false, fmt.Errorf("the hash is not base64")
		}
		if parts[0] == "argon2id" {
			actual = argon2.IDKey([]byte(req.Password), salt, uint32(values[0]), uint32(values[1]), uint8(values[2]), uint32(len(expected)))
		} else {
			actual = argon2.Key([]byte(req.Password), salt, uint32(values[0]), uint32(values[1]), uint8(values[2]), uint32(len(expected)))
		}
	default:
		return false, fmt.Errorf("the password hash is not one this action wrote")
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1, nil
}

func init() {
	sdk.RegisterImport(importer{})
}

func main() {}
