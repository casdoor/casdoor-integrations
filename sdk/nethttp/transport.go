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

// Package nethttp lets an action use Go libraries built on net/http, such as the official SDK of a payment service:
// pass Client() to the library, or set Transport on its client. It makes the module larger, so plain sdk.Fetch is
// the better choice when the action only makes a few calls.
package nethttp

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/casdoor/casdoor-integrations/sdk"
)

type Transport struct{}

func (Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	headers := map[string]string{}
	for key, values := range req.Header {
		headers[key] = strings.Join(values, ", ")
	}

	resp, err := sdk.Fetch(&sdk.Request{Method: req.Method, Url: req.URL.String(), Headers: headers, Body: body})
	if err != nil {
		return nil, err
	}

	header := http.Header{}
	for key, value := range resp.Headers {
		header.Set(key, value)
	}
	return &http.Response{
		Status:        http.StatusText(resp.Status),
		StatusCode:    resp.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(resp.Body)),
		ContentLength: int64(len(resp.Body)),
		Request:       req,
	}, nil
}

func Client() *http.Client {
	return &http.Client{Transport: Transport{}}
}
