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

// Package sdk is what a Casdoor action is written with. An action is a WebAssembly module built from a Go main
// package with GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared. Casdoor runs it in a sandbox: the module
// can only reach the hosts its manifest lists, through Fetch, and sees nothing of Casdoor but what each call passes in.
package sdk

import (
	"encoding/json"
	"fmt"
)

// Abi is the version of the calling convention between Casdoor and the module, written as "abi" in action.json.
const Abi = 1

type Request struct {
	Method  string            `json:"method"`
	Url     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// Config holds the fields of the Casdoor provider the action runs for, as the admin filled them in.
type Config struct {
	ClientId      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret"`
	ClientId2     string `json:"clientId2"`
	ClientSecret2 string `json:"clientSecret2"`
	Host          string `json:"host"`
	Metadata      string `json:"metadata"`
	SignName      string `json:"signName"`
	TemplateCode  string `json:"templateCode"`
}

type call struct {
	Abi    int             `json:"abi"`
	Method string          `json:"method"`
	Config *Config         `json:"config"`
	Params json.RawMessage `json:"params"`
}

type result struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

var handlers = map[string]func(config *Config, params json.RawMessage) (interface{}, error){}

func handle(input []byte) []byte {
	res := result{}
	c := call{}
	err := json.Unmarshal(input, &c)
	if err != nil {
		res.Error = err.Error()
	} else if c.Abi != Abi {
		res.Error = fmt.Sprintf("the action is built for abi %d, Casdoor called it with abi %d", Abi, c.Abi)
	} else if handler, ok := handlers[c.Method]; !ok {
		res.Error = fmt.Sprintf("the action does not implement %s", c.Method)
	} else {
		if c.Config == nil {
			c.Config = &Config{}
		}
		res.Result, err = handler(c.Config, c.Params)
		if err != nil {
			res.Result = nil
			res.Error = err.Error()
		}
	}

	output, err := json.Marshal(res)
	if err != nil {
		output, _ = json.Marshal(result{Error: err.Error()})
	}
	return output
}

// Fetch sends an HTTP request through Casdoor. Only https URLs on the hosts in the manifest's permissions.hosts work.
func Fetch(req *Request) (*Response, error) {
	input, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp := &Response{}
	err = json.Unmarshal(hostFetch(input), resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp, nil
}

// Log writes a line to the Casdoor log.
func Log(format string, args ...interface{}) {
	hostLog(fmt.Sprintf(format, args...))
}
