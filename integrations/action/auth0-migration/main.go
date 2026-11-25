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

// Auth0 migration reads an Auth0 tenant through the Management API for a Casdoor migration: the applications, the
// users with their social links, the organizations as groups with their members, and the roles with their users.
// Auth0 doesn't return password hashes through the API: the hashes file Auth0 support exports can be uploaded with
// the migration, its bcrypt hashes are what Casdoor checks.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/casdoor/casdoor-integrations/sdk"
)

const (
	usersPerPage = 100
	// the Management API returns at most 1000 users of one search
	maxSearchPages   = 10
	pagesPerCall     = 5
	rolesPerCall     = 5
	maxRetries       = 6
	maxRetryWaitSecs = 20
)

// the Auth0 identity providers that are a field of the Casdoor user, which its sign-in looks the user up by
var linkFields = map[string]string{
	"google-oauth2": "google",
	"github":        "github",
	"facebook":      "facebook",
	"windowslive":   "azuread",
	"apple":         "apple",
	"linkedin":      "linkedin",
	"twitter":       "twitter",
	"bitbucket":     "bitbucket",
	"discord":       "discord",
	"gitlab":        "gitlab",
	"paypal":        "paypal",
	"salesforce":    "salesforce",
	"dropbox":       "dropbox",
	"shopify":       "shopify",
	"slack":         "slack",
	"box":           "box",
}

var namePattern = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

type importer struct{}

type client struct {
	config *sdk.Config
	host   string
	token  string
}

type cursor struct {
	Token string `json:"token"`
	// users: the lower bound of created_at of the search and the page in it, and the users already read at the bound
	Lower string   `json:"lower,omitempty"`
	Page  int      `json:"page,omitempty"`
	Skip  []string `json:"skip,omitempty"`
	// no range search: plain pages, up to the 1000 users the search returns
	Plain bool `json:"plain,omitempty"`
	// checkpoint of the organizations and roles
	From  string `json:"from,omitempty"`
	Index int    `json:"index,omitempty"`
}

func getHost(config *sdk.Config) (string, error) {
	host := strings.TrimSpace(config.Host)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimRight(host, "/")
	if host == "" {
		return "", fmt.Errorf("set the host to the domain of the Auth0 tenant, such as your-tenant.us.auth0.com")
	}
	return host, nil
}

func newClient(config *sdk.Config, token string) (*client, error) {
	host, err := getHost(config)
	if err != nil {
		return nil, err
	}
	c := &client{config: config, host: host, token: token}
	if token != "" {
		return c, nil
	}
	if strings.TrimSpace(config.ClientId) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return nil, fmt.Errorf("set the client ID and secret of an Auth0 machine to machine application authorized for the Management API")
	}

	body, _ := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     strings.TrimSpace(config.ClientId),
		"client_secret": strings.TrimSpace(config.ClientSecret),
		"audience":      fmt.Sprintf("https://%s/api/v2/", host),
	})
	resp, err := c.send("POST", "/oauth/token", body)
	if err != nil {
		return nil, err
	}
	res := struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{}
	err = json.Unmarshal(resp.Body, &res)
	if err != nil || res.AccessToken == "" {
		if res.ErrorDescription != "" {
			return nil, fmt.Errorf("Auth0 refused the client: %s (%s)", res.ErrorDescription, res.Error)
		}
		return nil, fmt.Errorf("Auth0 returned no token: HTTP %d %s", resp.Status, string(resp.Body))
	}
	c.token = res.AccessToken
	return c, nil
}

func (c *client) send(method string, path string, body []byte) (*sdk.Response, error) {
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	if c.token != "" {
		headers["Authorization"] = "Bearer " + c.token
	}

	for attempt := 0; ; attempt++ {
		resp, err := sdk.Fetch(&sdk.Request{Method: method, Url: fmt.Sprintf("https://%s%s", c.host, path), Headers: headers, Body: body})
		if err != nil {
			return nil, err
		}
		if resp.Status != 429 || attempt >= maxRetries {
			return resp, nil
		}
		// the Management API rate limit: wait until the reset it gives
		wait := 1 << attempt
		if reset, err := strconv.ParseInt(getHeader(resp, "X-Ratelimit-Reset"), 10, 64); err == nil {
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

// get reads a Management API path, a 403 for a missing scope returns ok false so that the kind is skipped
func (c *client) get(path string, out interface{}) (bool, error) {
	resp, err := c.send("GET", path, nil)
	if err != nil {
		return false, err
	}
	if resp.Status == 403 {
		return false, nil
	}
	if resp.Status != 200 {
		return false, fmt.Errorf("GET %s: HTTP %d %s", path, resp.Status, string(resp.Body))
	}
	return true, json.Unmarshal(resp.Body, out)
}

func sanitize(name string) string {
	name = strings.Trim(namePattern.ReplaceAllString(strings.TrimSpace(name), "-"), "-")
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

// getUserName is the Casdoor name of an Auth0 user, from its user ID, which the members of roles and organizations
// are listed by too: auth0|64b1... becomes 64b1..., google-oauth2|1083... becomes google-oauth2-1083...
func getUserName(userId string) string {
	provider, id, ok := strings.Cut(userId, "|")
	if !ok {
		return sanitize(userId)
	}
	if provider == "auth0" {
		return sanitize(id)
	}
	return sanitize(provider + "-" + id)
}

func getRedirectUri(uri string) string {
	if !strings.Contains(uri, "*") {
		return uri
	}
	return strings.ReplaceAll(regexp.QuoteMeta(uri), `\*`, ".*")
}

func encodeCursor(c *cursor) string {
	data, _ := json.Marshal(c)
	return string(data)
}

func decodeCursor(value string) (*cursor, error) {
	c := &cursor{}
	if value == "" {
		return c, nil
	}
	err := json.Unmarshal([]byte(value), c)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	return c, nil
}

func (importer) List(config *sdk.Config, req *sdk.ImportListReq) (*sdk.ImportListResp, error) {
	cur, err := decodeCursor(req.Cursor)
	if err != nil {
		return nil, err
	}
	if req.Kind == "certs" || req.Kind == "permissions" {
		return listNotExported(config, req)
	}
	c, err := newClient(config, cur.Token)
	if err != nil {
		return nil, err
	}

	switch req.Kind {
	case "groups":
		return c.listOrganizations(cur)
	case "applications":
		return c.listApplications()
	case "users":
		return c.listUsers(cur, req.Files)
	case "roles":
		return c.listRoles(cur)
	}
	return &sdk.ImportListResp{Items: []interface{}{}}, nil
}

func listNotExported(config *sdk.Config, req *sdk.ImportListReq) (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	if req.Kind == "certs" {
		resp.Warnings = []string{
			"Auth0 doesn't export its signing keys, so the tokens Auth0 issued are not valid in Casdoor: users sign in again after the switch, and APIs that check tokens with Auth0's keys or issuer need Casdoor's",
			"Custom claims that Auth0 Actions or Rules add to tokens are not imported, add them to the applications' token fields or with Casdoor flows",
		}
	} else {
		resp.Warnings = []string{"The permissions of Auth0 APIs are not imported, the roles and their users are"}
	}
	return resp, nil
}

type organization struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

func (c *client) listOrganizations(cur *cursor) (*sdk.ImportListResp, error) {
	path := "/api/v2/organizations?take=50"
	if cur.From != "" {
		path += "&from=" + url.QueryEscape(cur.From)
	}
	page := struct {
		Organizations []*organization `json:"organizations"`
		Next          string          `json:"next"`
	}{}
	ok, err := c.get(path, &page)
	if err != nil {
		return nil, err
	}
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	if !ok {
		resp.Warnings = []string{"The organizations are not imported as groups: give the Auth0 application the read:organizations and read:organization_members scopes of the Management API to import them"}
		return resp, nil
	}

	for _, org := range page.Organizations {
		members := []string{}
		from := ""
		for {
			path := fmt.Sprintf("/api/v2/organizations/%s/members?take=100", url.PathEscape(org.Id))
			if from != "" {
				path += "&from=" + url.QueryEscape(from)
			}
			res := struct {
				Members []struct {
					UserId string `json:"user_id"`
				} `json:"members"`
				Next string `json:"next"`
			}{}
			ok, err := c.get(path, &res)
			if err != nil {
				return nil, err
			}
			if !ok {
				resp.Warnings = append(resp.Warnings, "The members of the organizations are not imported: give the Auth0 application the read:organization_members scope")
				break
			}
			for _, member := range res.Members {
				members = append(members, getUserName(member.UserId))
			}
			if res.Next == "" || len(res.Members) == 0 {
				break
			}
			from = res.Next
		}

		displayName := org.DisplayName
		if displayName == "" {
			displayName = org.Name
		}
		resp.Items = append(resp.Items, map[string]interface{}{
			"name":        sanitize(org.Name),
			"displayName": displayName,
			"type":        "Virtual",
			"users":       members,
			"properties":  map[string]string{"auth0_organization_id": org.Id},
		})
	}

	if page.Next != "" && len(page.Organizations) > 0 {
		resp.Cursor = encodeCursor(&cursor{Token: c.token, From: page.Next})
	}
	return resp, nil
}

type auth0Client struct {
	ClientId                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	AppType                 string   `json:"app_type"`
	LogoUri                 string   `json:"logo_uri"`
	Callbacks               []string `json:"callbacks"`
	InitiateLoginUri        string   `json:"initiate_login_uri"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Global                  bool     `json:"global"`
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
		case "authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code":
			add(grantType)
		case "implicit":
			add("token", "id_token")
		case "password", "http://auth0.com/oauth/grant-type/password-realm":
			add("password")
		}
	}
	return res
}

func (c *client) listApplications() (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	names := map[string]bool{}
	hasSecrets := true
	for page := 0; ; page++ {
		clients := []*auth0Client{}
		ok, err := c.get(fmt.Sprintf("/api/v2/clients?is_global=false&per_page=50&page=%d", page), &clients)
		if err != nil {
			return nil, err
		}
		if !ok {
			resp.Warnings = []string{"The applications are not imported: give the Auth0 application the read:clients and read:client_keys scopes of the Management API to import them"}
			return resp, nil
		}

		for _, app := range clients {
			// the machine to machine application the migration reads Auth0 with
			if app.Global || app.ClientId == strings.TrimSpace(c.config.ClientId) {
				continue
			}
			name := sanitize(app.Name)
			if name == "" || names[name] {
				name = sanitize(name + "-" + app.ClientId)
			}
			names[name] = true

			redirectUris := []string{}
			for _, uri := range app.Callbacks {
				redirectUris = append(redirectUris, getRedirectUri(uri))
			}
			item := map[string]interface{}{
				"name":         name,
				"displayName":  app.Name,
				"description":  app.Description,
				"logo":         app.LogoUri,
				"homepageUrl":  app.InitiateLoginUri,
				"clientId":     app.ClientId,
				"redirectUris": redirectUris,
				"grantTypes":   getGrantTypes(app.GrantTypes),
				"tokenFormat":  "JWT-Standard",
			}
			if app.TokenEndpointAuthMethod != "none" {
				if app.ClientSecret != "" {
					item["clientSecret"] = app.ClientSecret
				} else {
					hasSecrets = false
				}
			}
			resp.Items = append(resp.Items, item)
		}
		if len(clients) < 50 {
			break
		}
	}
	if !hasSecrets {
		resp.Warnings = append(resp.Warnings, "Auth0 returned no client secrets, so Casdoor gives the applications new ones: give the Auth0 application the read:client_keys scope to keep them")
	}
	return resp, nil
}

type auth0User struct {
	UserId        string                 `json:"user_id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Username      string                 `json:"username"`
	PhoneNumber   string                 `json:"phone_number"`
	Name          string                 `json:"name"`
	Nickname      string                 `json:"nickname"`
	GivenName     string                 `json:"given_name"`
	FamilyName    string                 `json:"family_name"`
	Picture       string                 `json:"picture"`
	Blocked       bool                   `json:"blocked"`
	CreatedAt     string                 `json:"created_at"`
	LastLogin     string                 `json:"last_login"`
	Multifactor   []string               `json:"multifactor"`
	AppMetadata   map[string]interface{} `json:"app_metadata"`
	UserMetadata  map[string]interface{} `json:"user_metadata"`
	Identities    []struct {
		Provider   string      `json:"provider"`
		UserId     interface{} `json:"user_id"`
		Connection string      `json:"connection"`
	} `json:"identities"`
}

// readHashes reads the password hashes Auth0 support exports, one JSON object a line, by user ID and by email
func readHashes(files []*sdk.ImportFile) (map[string]string, map[string]string, error) {
	byId, byEmail := map[string]string{}, map[string]string{}
	for _, file := range files {
		scanner := bufio.NewScanner(bytes.NewReader(file.Data))
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		line := 0
		for scanner.Scan() {
			line++
			text := strings.TrimSpace(scanner.Text())
			if text == "" || text == "[" || text == "]" {
				continue
			}
			text = strings.TrimSuffix(text, ",")
			entry := struct {
				Id struct {
					Oid string `json:"$oid"`
				} `json:"_id"`
				Email        string `json:"email"`
				PasswordHash string `json:"passwordHash"`
			}{}
			if err := json.Unmarshal([]byte(text), &entry); err != nil {
				return nil, nil, fmt.Errorf("line %d of %s is not a line of the Auth0 password hash export: %w", line, file.Name, err)
			}
			if entry.PasswordHash == "" {
				continue
			}
			if entry.Id.Oid != "" {
				byId["auth0|"+entry.Id.Oid] = entry.PasswordHash
			}
			if entry.Email != "" {
				byEmail[strings.ToLower(entry.Email)] = entry.PasswordHash
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file.Name, err)
		}
	}
	return byId, byEmail, nil
}

func toJson(value interface{}) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func getUserItem(user *auth0User, hashesById map[string]string, hashesByEmail map[string]string, counts map[string]int) map[string]interface{} {
	displayName := user.Name
	if displayName == "" {
		displayName = user.Nickname
	}
	if displayName == "" {
		displayName = user.Email
	}
	properties := map[string]string{}
	if user.Username != "" {
		properties["auth0_username"] = user.Username
	}
	if len(user.AppMetadata) > 0 {
		properties["auth0_app_metadata"] = toJson(user.AppMetadata)
	}
	if len(user.UserMetadata) > 0 {
		properties["auth0_user_metadata"] = toJson(user.UserMetadata)
	}

	item := map[string]interface{}{
		"id":             user.UserId,
		"name":           getUserName(user.UserId),
		"displayName":    displayName,
		"firstName":      user.GivenName,
		"lastName":       user.FamilyName,
		"avatar":         user.Picture,
		"email":          user.Email,
		"emailVerified":  user.EmailVerified,
		"phone":          user.PhoneNumber,
		"isForbidden":    user.Blocked,
		"createdTime":    user.CreatedAt,
		"lastSigninTime": user.LastLogin,
		"properties":     properties,
	}

	isDatabaseUser := false
	for _, identity := range user.Identities {
		id := fmt.Sprintf("%v", identity.UserId)
		if f, ok := identity.UserId.(float64); ok {
			id = strconv.FormatFloat(f, 'f', -1, 64)
		}
		if identity.Provider == "auth0" {
			isDatabaseUser = true
			continue
		}
		if field, ok := linkFields[identity.Provider]; ok {
			item[field] = id
		} else {
			properties[fmt.Sprintf("oauth_%s_id", identity.Provider)] = id
			counts[fmt.Sprintf("Users who sign in with %s keep the link as the property oauth_%s_id, add the provider to Casdoor to sign them in with it", identity.Provider, identity.Provider)]++
		}
	}

	if isDatabaseUser {
		hash := hashesById[user.UserId]
		if hash == "" && user.Email != "" {
			hash = hashesByEmail[strings.ToLower(user.Email)]
		}
		if hash != "" {
			item["password"], item["passwordType"] = hash, "bcrypt"
		} else {
			counts["%d users of Auth0 database connections have no password hash: upload the password hash export from Auth0 support with the migration, or they reset their passwords in Casdoor"]++
		}
	}
	if len(user.Multifactor) > 0 {
		counts["%d users enrolled in Auth0 MFA, whose factors Auth0 doesn't export, have to enroll again"]++
	}
	return item
}

func (c *client) listUsers(cur *cursor, files []*sdk.ImportFile) (*sdk.ImportListResp, error) {
	hashesById, hashesByEmail, err := readHashes(files)
	if err != nil {
		return nil, err
	}

	resp := &sdk.ImportListResp{Items: []interface{}{}}
	counts := map[string]int{}
	skip := map[string]bool{}
	for _, id := range cur.Skip {
		skip[id] = true
	}
	next := &cursor{Token: c.token, Lower: cur.Lower, Page: cur.Page, Skip: cur.Skip, Plain: cur.Plain}
	done := false

	for i := 0; i < pagesPerCall && !done; i++ {
		query := url.Values{}
		query.Set("per_page", strconv.Itoa(usersPerPage))
		query.Set("page", strconv.Itoa(next.Page))
		query.Set("sort", "created_at:1")
		query.Set("search_engine", "v3")
		if next.Lower != "" && !next.Plain {
			query.Set("q", fmt.Sprintf(`created_at:["%s" TO *]`, next.Lower))
		}

		users := []*auth0User{}
		resp2, err := c.send("GET", "/api/v2/users?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if resp2.Status == 400 && next.Lower != "" && !next.Plain {
			// the range search was refused, so only the first 1000 users can be read
			return nil, fmt.Errorf("Auth0 refused to search the users by creation time: %s", string(resp2.Body))
		}
		if resp2.Status == 403 {
			return nil, fmt.Errorf("give the Auth0 application the read:users scope of the Management API")
		}
		if resp2.Status != 200 {
			return nil, fmt.Errorf("GET /api/v2/users: HTTP %d %s", resp2.Status, string(resp2.Body))
		}
		err = json.Unmarshal(resp2.Body, &users)
		if err != nil {
			return nil, err
		}

		for _, user := range users {
			if skip[user.UserId] {
				continue
			}
			resp.Items = append(resp.Items, getUserItem(user, hashesById, hashesByEmail, counts))
		}

		if len(users) < usersPerPage {
			done = true
			break
		}
		next.Page++
		if next.Page >= maxSearchPages {
			// the search stops at 1000 users: the next one starts at the creation time of the last user, skipping
			// the users of that same millisecond that were already read
			last := users[len(users)-1].CreatedAt
			if last == "" {
				return nil, fmt.Errorf("the users have no creation time to page through more than 1000 of them")
			}
			ids := []string{}
			if last == next.Lower {
				ids = next.Skip
			}
			for _, user := range users {
				if user.CreatedAt == last {
					ids = append(ids, user.UserId)
				}
			}
			if last == next.Lower && len(ids) >= maxSearchPages*usersPerPage {
				return nil, fmt.Errorf("more than 1000 users were created at %s, Auth0 cannot list them through the API", last)
			}
			next.Lower, next.Page, next.Skip = last, 0, ids
			skip = map[string]bool{}
			for _, id := range ids {
				skip[id] = true
			}
		}
	}

	for format, count := range counts {
		if strings.Contains(format, "%d") {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf(format, count))
		} else {
			resp.Warnings = append(resp.Warnings, format)
		}
	}
	if !done {
		resp.Cursor = encodeCursor(next)
	}
	return resp, nil
}

type role struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (c *client) listRoles(cur *cursor) (*sdk.ImportListResp, error) {
	resp := &sdk.ImportListResp{Items: []interface{}{}}
	roles := []*role{}
	for page := 0; ; page++ {
		list := []*role{}
		ok, err := c.get(fmt.Sprintf("/api/v2/roles?per_page=50&page=%d", page), &list)
		if err != nil {
			return nil, err
		}
		if !ok {
			resp.Warnings = []string{"The roles are not imported: give the Auth0 application the read:roles and read:users scopes of the Management API to import them"}
			return resp, nil
		}
		roles = append(roles, list...)
		if len(list) < 50 {
			break
		}
	}

	end := cur.Index + rolesPerCall
	if end > len(roles) {
		end = len(roles)
	}
	for _, r := range roles[cur.Index:end] {
		users := []string{}
		from := ""
		for {
			path := fmt.Sprintf("/api/v2/roles/%s/users?take=100", url.PathEscape(r.Id))
			if from != "" {
				path += "&from=" + url.QueryEscape(from)
			}
			res := struct {
				Users []struct {
					UserId string `json:"user_id"`
				} `json:"users"`
				Next string `json:"next"`
			}{}
			_, err := c.get(path, &res)
			if err != nil {
				return nil, err
			}
			for _, user := range res.Users {
				users = append(users, getUserName(user.UserId))
			}
			if res.Next == "" || len(res.Users) == 0 {
				break
			}
			from = res.Next
		}
		resp.Items = append(resp.Items, map[string]interface{}{
			"name":        sanitize(r.Name),
			"displayName": r.Name,
			"description": r.Description,
			"users":       users,
			"isEnabled":   true,
		})
	}
	if end < len(roles) {
		resp.Cursor = encodeCursor(&cursor{Token: c.token, Index: end})
	}
	return resp, nil
}

func (importer) Test(config *sdk.Config, files []*sdk.ImportFile) error {
	if _, _, err := readHashes(files); err != nil {
		return err
	}
	c, err := newClient(config, "")
	if err != nil {
		return err
	}
	users := []*auth0User{}
	resp, err := c.send("GET", "/api/v2/users?per_page=1&page=0&search_engine=v3", nil)
	if err != nil {
		return err
	}
	if resp.Status == 403 {
		return fmt.Errorf("the token works, give the Auth0 application the read:users scope of the Management API")
	}
	if resp.Status != 200 {
		return fmt.Errorf("GET /api/v2/users: HTTP %d %s", resp.Status, string(resp.Body))
	}
	return json.Unmarshal(resp.Body, &users)
}

func init() {
	sdk.RegisterImport(importer{})
}

func main() {}
