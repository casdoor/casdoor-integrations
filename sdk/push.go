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

// SendPushReq is a sign-in waiting for the user to confirm it on the phone: the action shows Title and Description
// to Receiver, with a button that opens Url, where the user approves or denies the sign-in.
type SendPushReq struct {
	Receiver    string `json:"receiver"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Url         string `json:"url"`
}

// PushSender is an action of kind "push", such as an app message of WeCom, DingTalk or Lark.
type PushSender interface {
	SendPush(config *Config, req *SendPushReq) error
}

// RegisterPush makes the action a push sender. Call it from init.
func RegisterPush(sender PushSender) {
	handlers["push.send"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &SendPushReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return nil, sender.SendPush(config, req)
	}
}
