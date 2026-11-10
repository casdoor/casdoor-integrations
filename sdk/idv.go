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

// IdvRequest is the identity a user claims: the ID card, the real name and, for checks that include it, the phone.
type IdvRequest struct {
	IdCardType string `json:"idCardType"`
	IdCard     string `json:"idCard"`
	RealName   string `json:"realName"`
	Phone      string `json:"phone"`
}

// IdvResult is the answer of the verification service. When the identity does not match, Ok is false and Reason
// tells the user why; an error is only for a call that failed.
type IdvResult struct {
	Ok     bool   `json:"ok"`
	Reason string `json:"reason"`
}

// IdentityVerifier is an action of kind "idv", a real-name verification such as an ID card and name check.
type IdentityVerifier interface {
	Verify(config *Config, req *IdvRequest) (*IdvResult, error)
}

// RegisterIdv makes the action an identity verifier. Call it from init.
func RegisterIdv(verifier IdentityVerifier) {
	handlers["idv.verify"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &IdvRequest{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return verifier.Verify(config, req)
	}
}
