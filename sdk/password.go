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

// CheckPasswordReq is a password being set or used to sign in, which a password check action judges.
type CheckPasswordReq struct {
	Password string `json:"password"`
	Username string `json:"username"`
	// true when the user signs in with the password, false when the password is being set
	IsSignin bool `json:"isSignin"`
}

// CheckPasswordResp refuses the password when Ok is false, telling the user why in Reason.
type CheckPasswordResp struct {
	Ok     bool   `json:"ok"`
	Reason string `json:"reason"`
}

// PasswordChecker is an action of kind "password-check", such as a check against leaked or common passwords.
type PasswordChecker interface {
	CheckPassword(config *Config, req *CheckPasswordReq) (*CheckPasswordResp, error)
}

// RegisterPasswordCheck makes the action a password check. Call it from init.
func RegisterPasswordCheck(checker PasswordChecker) {
	handlers["password.check"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &CheckPasswordReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return checker.CheckPassword(config, req)
	}
}

// VerifyPasswordReq is the first sign-in of a user imported without a password: the old system tells whether the
// password is right, and Casdoor keeps it from then on. config.Host is the address the admin filled in.
type VerifyPasswordReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type VerifyPasswordResp struct {
	Valid bool `json:"valid"`
}

// PasswordVerifier is an action of kind "password-migration".
type PasswordVerifier interface {
	VerifyPassword(config *Config, req *VerifyPasswordReq) (*VerifyPasswordResp, error)
}

// RegisterPasswordVerify makes the action a password migration. Call it from init.
func RegisterPasswordVerify(verifier PasswordVerifier) {
	handlers["password.verify"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &VerifyPasswordReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return verifier.VerifyPassword(config, req)
	}
}
