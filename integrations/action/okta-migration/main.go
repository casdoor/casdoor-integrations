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

// Okta migration reads an Okta org through the Okta API with an API token for a Casdoor migration: the users, the
// groups with their members and the OpenID Connect applications with their client IDs and secrets. Okta never exports
// password hashes, so the users keep their passwords another way: on a user's first sign-in to Casdoor, the action
// checks the password with Okta's authentication API, and Casdoor then stores it its own way.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casdoor/casdoor-integrations/sdk"
)

const (
	usersPerPage     = 200
	groupsPerPage    = 50
	appsPerPage      = 100
	maxRetries       = 6
	maxRetryWaitSecs = 20
)

var (
	namePattern = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
	// a user name Casdoor accepts as it is: a plain name or an email address
	userNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.+-]+(@[a-zA-Z0-9.-]+)?$`)
	nextLinkPattern = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)
)

// the profile attributes of an Okta user that go into fields of the Casdoor user, the others become properties
var mappedProfileFields = map[string]bool{
	"login": true, "email": true, "firstName": true, "lastName": true, "displayName": true, "nickName": true,
	"mobilePhone": true, "primaryPhone": true, "title": true, "organization": true, "preferredLanguage": true,
	"locale": true, "secondEmail": true,
}

type importer struct{}

type client struct {
	host  string
	token string
}

func getHost(config *sdk.Config) (string, error) {
	host := strings.TrimSpace(config.Host)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimRight(host, "/")
	host = strings.TrimSuffix(host, "/api/v1")
	if host == "" {
		return "", fmt.Errorf("set the host to the domain of the Okta org, such as your-org.okta.com")
	}
	return host, nil
}

func newClient(config *sdk.Config) (*client, error) {
	host, err := getHost(config)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(config.ClientSecret)
	token = strings.TrimSpace(strings.TrimPrefix(token, "SSWS "))
	if token == "" {
		return nil, fmt.Errorf("set the client secret to an API token of the Okta org, created under Security > API > Tokens")
	}
	return &client{host: host, token: token}, nil
}

func (c *client) send(method string, path string, body []byte, withToken bool) (*sdk.Response, error) {
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	if withToken {
		headers["Authorization"] = "SSWS " + c.token
	}

	for attempt := 0; ; attempt++ {
		resp, err := sdk.Fetch(&sdk.Request{Method: method, Url: fmt.Sprintf("https://%s%s", c.host, path), Headers: headers, Body: body})
		if err != nil {
			return nil, err
		}
		if resp.Status != 429 || attempt >= maxRetries {
			return resp, nil
		}
		// the rate limit of Okta: wait until the reset it gives
		wait := 1 << attempt
		if reset, err := strconv.ParseInt(getHeader(resp, "X-Rate-Limit-Reset"), 10, 64); err == nil {
			if secs := int(reset - time.Now().Unix()); secs > 0 {
				wait = secs
			}
		}
		if wait > maxRetryWaitSecs {
			wait = maxRetryWaitSecs
		}
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

func getHeader(resp *sdk.Response, name string) string {
	for key, value := range resp.Headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// get reads a path of the Okta API and returns the path of the next page from the Link header, "" on the last page
func (c *client) get(path string, out interface{}) (string, error) {
	resp, err := c.send("GET", path, nil, true)
	if err != nil {
		return "", err
	}
	if resp.Status == 401 {
		return "", fmt.Errorf("Okta refused the API token: HTTP 401 %s", string(resp.Body))
	}
	if resp.Status == 403 {
		return "", fmt.Errorf("the API token can't read %s: HTTP 403, create the token as a super admin or an admin who can read users, groups and apps", strings.SplitN(path, "?", 2)[0])
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("GET %s: HTTP %d %s", path, resp.Status, string(resp.Body))
	}
	err = json.Unmarshal(resp.Body, out)
	if err != nil {
		return "", err
	}
	return c.getNextPath(getHeader(resp, "Link")), nil
}

func (c *client) getNextPath(link string) string {
	match := nextLinkPattern.FindStringSubmatch(link)
	if match == nil {
		return ""
	}
	u, err := url.Parse(match[1])
	if err != nil || (u.Host != "" && !strings.EqualFold(u.Host, c.host)) {
		return ""
	}
	return u.RequestURI()
}

func sanitize(name string) string {
	name = strings.Trim(namePattern.ReplaceAllString(strings.TrimSpace(name), "-"), "-")
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

// getUserName is the Casdoor name of an Okta user, its login when Casdoor accepts it, which is often the email
func getUserName(login string) string {
	login = strings.TrimSpace(login)
	if userNamePattern.MatchString(login) && len(login) <= 100 {
		return login
	}
	return sanitize(login)
}

func getRedirectUri(uri string) string {
	if !strings.Contains(uri, "*") {
		return uri
	}
	return strings.ReplaceAll(regexp.QuoteMeta(uri), `\*`, ".*")
}

func getString(profile map[string]interface{}, key string) string {
	if value, ok := profile[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func addWarnings(resp *sdk.ImportListResp, counts map[string]int) {
	formats := []string{}
	for format := range counts {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	for _, format := range formats {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf(format, counts[format]))
	}
}

func (importer) List(config *sdk.Config, req *sdk.ImportListReq) (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	switch req.Kind {
	case "certs":
		resp.Warnings = []string{
			"Okta doesn't export its signing keys, so the tokens Okta issued are not valid in Casdoor: users sign in again after the switch, and APIs that check tokens with Okta's keys or issuer need Casdoor's",
			"Okta doesn't export the MFA factors of the users: users who use MFA enroll again in Casdoor",
		}
		return resp, nil
	case "roles", "permissions":
		if req.Kind == "roles" {
			resp.Warnings = []string{"Okta admin roles, authorization servers, policies and the access of groups to applications are not imported, the groups and their members are"}
		}
		return resp, nil
	}

	c, err := newClient(config)
	if err != nil {
		return nil, err
	}
	switch req.Kind {
	case "groups":
		return c.listGroups(req.Cursor)
	case "applications":
		return c.listApplications(req.Cursor)
	case "users":
		return c.listUsers(req.Cursor)
	}
	return resp, nil
}

type oktaGroup struct {
	Id      string `json:"id"`
	Type    string `json:"type"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

type oktaUser struct {
	Id          string                 `json:"id"`
	Status      string                 `json:"status"`
	Created     string                 `json:"created"`
	Profile     map[string]interface{} `json:"profile"`
	Credentials *struct {
		Password *json.RawMessage `json:"password"`
		Provider *struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"provider"`
	} `json:"credentials"`
}

func getPage(cursor string, firstPage string) string {
	if cursor != "" {
		return cursor
	}
	return firstPage
}

func (c *client) listGroups(cursor string) (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	groups := []*oktaGroup{}
	next, err := c.get(getPage(cursor, fmt.Sprintf("/api/v1/groups?limit=%d", groupsPerPage)), &groups)
	if err != nil {
		return nil, err
	}

	names := map[string]bool{}
	for _, group := range groups {
		// the group "Everyone" that every user is in
		if group.Type == "BUILT_IN" {
			continue
		}
		users := []string{}
		path := fmt.Sprintf("/api/v1/groups/%s/users?limit=%d", url.PathEscape(group.Id), usersPerPage)
		for path != "" {
			members := []*oktaUser{}
			path, err = c.get(path, &members)
			if err != nil {
				return nil, err
			}
			for _, member := range members {
				users = append(users, getUserName(getString(member.Profile, "login")))
			}
		}

		name := sanitize(group.Profile.Name)
		if name == "" || names[name] {
			name = sanitize(name + "-" + group.Id)
		}
		names[name] = true
		resp.Items = append(resp.Items, map[string]interface{}{
			"name":        name,
			"displayName": group.Profile.Name,
			"type":        "Virtual",
			"users":       users,
			"isEnabled":   true,
			"properties":  map[string]string{"okta_id": group.Id},
		})
	}
	resp.Cursor = next
	return resp, nil
}

type oktaApp struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	SignOnMode string `json:"signOnMode"`
	Settings   struct {
		OauthClient *struct {
			ClientUri    string   `json:"client_uri"`
			LogoUri      string   `json:"logo_uri"`
			RedirectUris []string `json:"redirect_uris"`
			GrantTypes   []string `json:"grant_types"`
			InitiateUri  string   `json:"initiate_login_uri"`
		} `json:"oauthClient"`
	} `json:"settings"`
	Credentials struct {
		OauthClient *struct {
			ClientId                string `json:"client_id"`
			ClientSecret            string `json:"client_secret"`
			TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
		} `json:"oauthClient"`
	} `json:"credentials"`
}

func getGrantTypes(grantTypes []string) []string {
	res := []string{}
	add := func(values ...string) {
		for _, value := range values {
			found := false
			for _, existing := range res {
				found = found || existing == value
			}
			if !found {
				res = append(res, value)
			}
		}
	}
	for _, grantType := range grantTypes {
		switch grantType {
		case "authorization_code", "refresh_token", "client_credentials", "password", "urn:ietf:params:oauth:grant-type:device_code":
			add(grantType)
		case "implicit":
			add("token", "id_token")
		}
	}
	return res
}

// getClientSecret is the active client secret of an application, from the secrets of its credentials when the
// application itself doesn't show it
func (c *client) getClientSecret(app *oktaApp) (string, error) {
	if secret := app.Credentials.OauthClient.ClientSecret; secret != "" {
		return secret, nil
	}
	resp, err := c.send("GET", fmt.Sprintf("/api/v1/apps/%s/credentials/secrets", url.PathEscape(app.Id)), nil, true)
	if err != nil {
		return "", err
	}
	if resp.Status != 200 {
		return "", nil
	}
	secrets := []struct {
		Status       string `json:"status"`
		ClientSecret string `json:"client_secret"`
	}{}
	if json.Unmarshal(resp.Body, &secrets) != nil {
		return "", nil
	}
	for _, secret := range secrets {
		if secret.Status == "ACTIVE" && secret.ClientSecret != "" {
			return secret.ClientSecret, nil
		}
	}
	return "", nil
}

func (c *client) listApplications(cursor string) (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	apps := []*oktaApp{}
	next, err := c.get(getPage(cursor, fmt.Sprintf("/api/v1/apps?limit=%d", appsPerPage)), &apps)
	if err != nil {
		return nil, err
	}

	counts := map[string]int{}
	others := []string{}
	for _, app := range apps {
		// the apps of Okta itself, such as the admin console and the end-user dashboard
		if app.Name == "saasure" || strings.HasPrefix(app.Name, "okta_") {
			continue
		}
		if app.SignOnMode != "OPENID_CONNECT" || app.Credentials.OauthClient == nil || app.Settings.OauthClient == nil {
			others = append(others, app.Label)
			continue
		}

		oauthClient := app.Settings.OauthClient
		redirectUris := []string{}
		for _, uri := range oauthClient.RedirectUris {
			redirectUris = append(redirectUris, getRedirectUri(uri))
		}
		name := sanitize(app.Label)
		if name == "" {
			name = app.Credentials.OauthClient.ClientId
		}
		item := map[string]interface{}{
			"name":         name,
			"displayName":  app.Label,
			"logo":         oauthClient.LogoUri,
			"homepageUrl":  oauthClient.ClientUri,
			"clientId":     app.Credentials.OauthClient.ClientId,
			"redirectUris": redirectUris,
			"grantTypes":   getGrantTypes(oauthClient.GrantTypes),
			"tokenFormat":  "JWT-Standard",
		}
		switch app.Credentials.OauthClient.TokenEndpointAuthMethod {
		case "none":
		case "client_secret_basic", "client_secret_post", "client_secret_jwt", "":
			secret, err := c.getClientSecret(app)
			if err != nil {
				return nil, err
			}
			if secret != "" {
				item["clientSecret"] = secret
			} else {
				counts["Okta returned no client secrets of %d applications, so Casdoor gives them new ones: create the API token as a super admin to keep them"]++
			}
		default:
			counts["%d applications authenticate with a private key in Okta, Casdoor gives them client secrets instead"]++
		}
		if app.Status != "ACTIVE" {
			item["isEnabled"] = false
		}
		resp.Items = append(resp.Items, item)
	}

	addWarnings(resp, counts)
	if len(others) > 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("%d applications are not OpenID Connect applications and are not imported: %s", len(others), strings.Join(others, ", ")))
	}
	resp.Cursor = next
	return resp, nil
}

func getUserItem(user *oktaUser, counts map[string]int) map[string]interface{} {
	profile := user.Profile
	if profile == nil {
		profile = map[string]interface{}{}
	}
	login := getString(profile, "login")
	email := getString(profile, "email")
	firstName, lastName := getString(profile, "firstName"), getString(profile, "lastName")
	displayName := getString(profile, "displayName")
	if displayName == "" {
		displayName = strings.TrimSpace(firstName + " " + lastName)
	}
	if displayName == "" {
		displayName = login
	}
	phone := getString(profile, "mobilePhone")
	if phone == "" {
		phone = getString(profile, "primaryPhone")
	}
	language := getString(profile, "preferredLanguage")
	if language == "" {
		language = getString(profile, "locale")
	}

	properties := map[string]string{"okta_login": login}
	for key, value := range profile {
		if mappedProfileFields[key] || value == nil {
			continue
		}
		switch v := value.(type) {
		case string:
			if v != "" {
				properties[key] = v
			}
		default:
			data, _ := json.Marshal(v)
			properties[key] = string(data)
		}
	}
	if secondEmail := getString(profile, "secondEmail"); secondEmail != "" {
		properties["secondEmail"] = secondEmail
	}

	item := map[string]interface{}{
		"id":          user.Id,
		"name":        getUserName(login),
		"displayName": displayName,
		"firstName":   firstName,
		"lastName":    lastName,
		"email":       email,
		"phone":       phone,
		"title":       getString(profile, "title"),
		"affiliation": getString(profile, "organization"),
		"language":    language,
		"createdTime": user.Created,
		"isForbidden": user.Status == "SUSPENDED",
		"properties":  properties,
	}

	providerType := ""
	hasPassword := false
	if user.Credentials != nil {
		hasPassword = user.Credentials.Password != nil
		if user.Credentials.Provider != nil {
			providerType = user.Credentials.Provider.Type
		}
	}
	switch {
	case user.Status == "STAGED" || user.Status == "PROVISIONED":
		counts["%d users never activated their Okta account and have no password: they set one in Casdoor"]++
	case providerType == "FEDERATION" || providerType == "SOCIAL":
		counts["%d users sign in to Okta through an identity provider and have no Okta password: add the provider to the Casdoor applications"]++
	case hasPassword || providerType == "ACTIVE_DIRECTORY" || providerType == "LDAP":
		// Okta never exports hashes: the "hash" is the login that Okta checks the password of
		item["password"] = login
		item["passwordType"] = "plugin"
		counts["%d users keep their Okta password: Casdoor checks it with Okta on their first sign-in and then stores it, so keep Okta and this migration until they have signed in"]++
	default:
		counts["%d users have no password in Okta"]++
	}
	return item
}

func (c *client) listUsers(cursor string) (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	users := []*oktaUser{}
	next, err := c.get(getPage(cursor, fmt.Sprintf("/api/v1/users?limit=%d", usersPerPage)), &users)
	if err != nil {
		return nil, err
	}

	counts := map[string]int{}
	for _, user := range users {
		resp.Items = append(resp.Items, getUserItem(user, counts))
	}
	addWarnings(resp, counts)
	resp.Cursor = next
	return resp, nil
}

func (importer) Test(config *sdk.Config, files []*sdk.ImportFile) error {
	c, err := newClient(config)
	if err != nil {
		return err
	}
	users := []*oktaUser{}
	_, err = c.get("/api/v1/users?limit=1", &users)
	return err
}

// VerifyImportedPassword checks the password of a user with Okta's authentication API, the hash is the user's login
func (importer) VerifyImportedPassword(req *sdk.VerifyImportedPasswordReq) (bool, error) {
	if req.Config == nil || strings.TrimSpace(req.Config.Host) == "" {
		return false, fmt.Errorf("the migration from Okta is not found, its host is where the password is checked")
	}
	host, err := getHost(req.Config)
	if err != nil {
		return false, err
	}
	c := &client{host: host}

	body, _ := json.Marshal(map[string]string{"username": req.Hash, "password": req.Password})
	resp, err := c.send("POST", "/api/v1/authn", body, false)
	if err != nil {
		return false, err
	}
	switch resp.Status {
	case 200:
		res := struct {
			Status string `json:"status"`
		}{}
		err = json.Unmarshal(resp.Body, &res)
		if err != nil {
			return false, err
		}
		// MFA_REQUIRED, PASSWORD_EXPIRED and the like come after a correct password
		return res.Status != "" && res.Status != "LOCKED_OUT", nil
	case 401:
		return false, nil
	}
	return false, fmt.Errorf("POST /api/v1/authn: HTTP %d %s", resp.Status, string(resp.Body))
}

func init() {
	sdk.RegisterImport(importer{})
}

func main() {}
