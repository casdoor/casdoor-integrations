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

package sdk

import "encoding/json"

// ImportFile is a file the admin uploaded on the migration page, such as a realm export of the other system.
type ImportFile struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// ImportListReq asks for a page of one kind of objects. Casdoor asks for the kinds in this order: "certs", "groups",
// "applications", "users", "roles" and "permissions", and for each kind, starting with an empty cursor, asks again
// with the returned cursor until it is empty.
type ImportListReq struct {
	Kind   string `json:"kind"`
	Cursor string `json:"cursor"`
	// the Casdoor organization the objects go into
	Organization string        `json:"organization"`
	Files        []*ImportFile `json:"files"`
}

// ImportListResp holds the objects in the JSON of Casdoor's own objects: a cert, group, application, user, role or
// permission as Casdoor's API returns it. Casdoor sets the owner and organization itself and only adds the objects
// that don't exist yet.
//
// A user keeps its "id", which is the sub of its tokens, so take it from the other system. Its groups, and the users,
// groups and roles of a role or permission, are names in the organization. A group may list its members in "users"
// instead, for a system that keeps the memberships on the groups. The password is a hash in "password" and
// "passwordSalt" with "passwordType" set to a type Casdoor checks itself (such as "bcrypt" or "pbkdf2-salt"), or to
// "plugin" for a hash only the action can check through VerifyImportedPassword. A user signing in with a "plugin"
// password gets it rehashed the way the organization stores passwords.
//
// A warning that starts with a count, such as "3 users have no password hash", is added up with the same warning of
// the other pages.
type ImportListResp struct {
	Items    []interface{} `json:"items"`
	Cursor   string        `json:"cursor"`
	Warnings []string      `json:"warnings"`
}

// VerifyImportedPasswordReq is a sign-in of a user whose password type is "plugin": Hash and Salt are what the action
// returned as the user's password and passwordSalt.
type VerifyImportedPasswordReq struct {
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Salt     string `json:"salt"`
	// the migration's host, client ID, client secret and metadata, for an action that checks the password with the
	// other system
	Config *Config `json:"-"`
}

// Importer is an action of kind "import", which reads another identity system for a migration. The migration's host,
// client ID, client secret and metadata arrive in the config.
type Importer interface {
	List(config *Config, req *ImportListReq) (*ImportListResp, error)
}

// ImportTester is an Importer that can check the connection or the files before the migration is previewed.
type ImportTester interface {
	Test(config *Config, files []*ImportFile) error
}

// ImportedPasswordVerifier is an Importer that returns password hashes Casdoor doesn't know.
type ImportedPasswordVerifier interface {
	VerifyImportedPassword(req *VerifyImportedPasswordReq) (bool, error)
}

// RegisterImport makes the action an importer. Call it from init.
func RegisterImport(importer Importer) {
	handlers["import.list"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &ImportListReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return importer.List(config, req)
	}
	if tester, ok := importer.(ImportTester); ok {
		handlers["import.test"] = func(config *Config, params json.RawMessage) (interface{}, error) {
			req := struct {
				Files []*ImportFile `json:"files"`
			}{}
			err := json.Unmarshal(params, &req)
			if err != nil {
				return nil, err
			}
			return nil, tester.Test(config, req.Files)
		}
	}
	if verifier, ok := importer.(ImportedPasswordVerifier); ok {
		handlers["import.verifyPassword"] = func(config *Config, params json.RawMessage) (interface{}, error) {
			req := &VerifyImportedPasswordReq{}
			err := json.Unmarshal(params, req)
			if err != nil {
				return nil, err
			}
			req.Config = config
			valid, err := verifier.VerifyImportedPassword(req)
			return map[string]bool{"valid": valid}, err
		}
	}
}
