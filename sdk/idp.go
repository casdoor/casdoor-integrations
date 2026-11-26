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

// IdpToken is what the platform gave for the authorization code. Extra carries anything GetUserInfo needs besides
// the access token, such as the code itself when the platform looks the user up by it.
type IdpToken struct {
	AccessToken  string            `json:"accessToken"`
	RefreshToken string            `json:"refreshToken"`
	ExpiresIn    int               `json:"expiresIn"`
	Extra        map[string]string `json:"extra"`
}

// IdpUser is the user who signed in on the platform. Id is the user's stable ID there.
type IdpUser struct {
	Id          string            `json:"id"`
	Username    string            `json:"username"`
	DisplayName string            `json:"displayName"`
	Email       string            `json:"email"`
	Phone       string            `json:"phone"`
	CountryCode string            `json:"countryCode"`
	Avatar      string            `json:"avatar"`
	Extra       map[string]string `json:"extra"`
}

// IdentityProvider is an action of kind "idp", a third-party sign-in with an authorization code. The admin writes
// the platform's authorization page into the provider's Auth URL, with the placeholders {clientId}, {redirectUri},
// {state} and {scope}; the action only turns the code into the user. config.ClientId and config.ClientSecret are
// the app's key and secret, config.ClientId2 and config.ClientSecret2 a second pair if the platform needs one,
// config.Host the platform's address for a private deployment and config.Metadata any other settings, as JSON.
type IdentityProvider interface {
	GetToken(config *Config, code string, redirectUri string) (*IdpToken, error)
	GetUserInfo(config *Config, token *IdpToken) (*IdpUser, error)
}

// IdpChallengeRequest asks a ChallengeIdentityProvider for a challenge. Origin is the sign-in page, such as
// https://door.casdoor.com, Application the name of the application shown on it and Input what the sign-in script
// sent with getChallenge.
type IdpChallengeRequest struct {
	Origin      string            `json:"origin"`
	Application string            `json:"application"`
	Input       map[string]string `json:"input"`
}

// ChallengeIdentityProvider is an identity provider that signs in on the sign-in page itself, such as a crypto wallet,
// instead of on an authorization page. The action ships a sign-in script (the "script" of action.json, a JavaScript
// module whose default export is called with the casdoor object below) that asks Casdoor for a challenge, has the user
// answer it and finishes with the answer as the code:
//
//	export default async function signIn(casdoor) {
//	  // casdoor.application, casdoor.provider, casdoor.method ("signin", "signup" or "link"), casdoor.language
//	  const challenge = await casdoor.getChallenge({address: "..."}); // GetChallenge with this input
//	  casdoor.finish(answer);                                         // GetTokenWithChallenge with this code
//	}
//
// Casdoor keeps the challenge in the session of the browser for 5 minutes and passes it back once.
type ChallengeIdentityProvider interface {
	IdentityProvider
	GetChallenge(config *Config, req *IdpChallengeRequest) (string, error)
	// GetTokenWithChallenge checks that code answers challenge, "" when the browser has no challenge or it expired
	GetTokenWithChallenge(config *Config, code string, challenge string) (*IdpToken, error)
}

// RegisterIdp makes the action an identity provider. Call it from init.
func RegisterIdp(p IdentityProvider) {
	handlers["idp.getToken"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := struct {
			Code        string `json:"code"`
			RedirectUri string `json:"redirectUri"`
			Challenge   string `json:"challenge"`
		}{}
		err := json.Unmarshal(params, &req)
		if err != nil {
			return nil, err
		}
		if cp, ok := p.(ChallengeIdentityProvider); ok {
			return cp.GetTokenWithChallenge(config, req.Code, req.Challenge)
		}
		return p.GetToken(config, req.Code, req.RedirectUri)
	}
	if cp, ok := p.(ChallengeIdentityProvider); ok {
		handlers["idp.getChallenge"] = func(config *Config, params json.RawMessage) (interface{}, error) {
			req := &IdpChallengeRequest{}
			err := json.Unmarshal(params, req)
			if err != nil {
				return nil, err
			}
			challenge, err := cp.GetChallenge(config, req)
			if err != nil {
				return nil, err
			}
			return map[string]string{"challenge": challenge}, nil
		}
	}
	handlers["idp.getUserInfo"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := struct {
			Token *IdpToken `json:"token"`
		}{}
		err := json.Unmarshal(params, &req)
		if err != nil {
			return nil, err
		}
		if req.Token == nil {
			req.Token = &IdpToken{}
		}
		return p.GetUserInfo(config, req.Token)
	}
}
