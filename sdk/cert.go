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

// CertVerifyRequest is a certificate sign-in to check. The binary values are in base64.
type CertVerifyRequest struct {
	// the DER certificates the user presented, the user's own one first
	Certificates []string `json:"certificates"`
	// the PEM certificates of the organization's trusted CAs
	TrustedCas string `json:"trustedCas"`
	// the DER or PEM CRLs that Casdoor fetched from the organization's CRL URLs
	Crls []string `json:"crls"`
	// for a UKey plug-in: the challenge and the signature the UKey made of it, empty otherwise
	Message   string `json:"message,omitempty"`
	Signature string `json:"signature,omitempty"`
	// the current time in RFC 3339
	Time string `json:"time"`
}

// Reasons of a certificate that is not valid.
const (
	CertReasonExpired   = "expired"
	CertReasonUntrusted = "untrusted"
	CertReasonRevoked   = "revoked"
	CertReasonSignature = "signature"
	CertReasonInvalid   = "invalid"
)

// CertVerifyResult says whether the sign-in is valid and, when it is, the fields of the user's certificate that
// Casdoor matches to a user: CN, SERIALNUMBER, Email, UID and Fingerprint (the SHA-256 of the DER in hex). An error is
// only for a call that failed.
type CertVerifyResult struct {
	Valid  bool              `json:"valid"`
	Reason string            `json:"reason"`
	Detail string            `json:"detail"`
	Fields map[string]string `json:"fields"`
}

// CertVerifier is an action of kind "cert", which checks the certificates of certificate login for the algorithms
// that Casdoor doesn't verify itself.
type CertVerifier interface {
	Verify(req *CertVerifyRequest) (*CertVerifyResult, error)
}

// RegisterCert makes the action a certificate verifier. Call it from init.
func RegisterCert(verifier CertVerifier) {
	handlers["cert.verify"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &CertVerifyRequest{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return verifier.Verify(req)
	}
}
