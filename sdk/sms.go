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

// SendSmsReq is a message Casdoor wants sent. Params holds the values for the template, "code" being the
// verification code; the template itself is config.TemplateCode, and the sender config.SignName.
type SendSmsReq struct {
	Params map[string]string `json:"params"`

	// in E.164, such as +447700900123
	PhoneNumbers []string `json:"phoneNumbers"`
}

// SmsProvider is an SMS service. SendSms returns an error unless the service accepted the message for every number.
type SmsProvider interface {
	SendSms(config *Config, req *SendSmsReq) error
}

// RegisterSms makes the action an SMS provider. Call it from init.
func RegisterSms(provider SmsProvider) {
	handlers["sms.send"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &SendSmsReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return nil, provider.SendSms(config, req)
	}
}
