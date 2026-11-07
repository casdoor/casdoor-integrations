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

// Vonage sends SMS through the Vonage SMS API, one request per phone number.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/casdoor/casdoor-integrations/sdk"
)

const (
	apiUrl          = "https://rest.nexmo.com/sms/json"
	defaultTemplate = "Your verification code is %s."
)

// the GSM 03.38 alphabet with its extension table; any other character makes Vonage send the message as unicode
const gsmChars = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\fÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà^{}\\[~]|€"

type vonage struct{}

type message struct {
	To        string `json:"to"`
	MessageId string `json:"message-id"`
	Status    string `json:"status"`
	ErrorText string `json:"error-text"`
}

type smsResponse struct {
	Messages []message `json:"messages"`
}

func getText(config *sdk.Config, params map[string]string) (string, error) {
	template := strings.TrimSpace(config.TemplateCode)
	if template == "" {
		template = defaultTemplate
	}
	if !strings.Contains(template, "%s") {
		return "", fmt.Errorf("the template code must contain %%s where the verification code goes, such as: %s", defaultTemplate)
	}
	return strings.Replace(template, "%s", params["code"], 1), nil
}

func isGsm(text string) bool {
	for _, r := range text {
		if !strings.ContainsRune(gsmChars, r) {
			return false
		}
	}
	return true
}

func send(config *sdk.Config, from string, to string, text string) error {
	form := url.Values{}
	form.Set("api_key", strings.TrimSpace(config.ClientId))
	form.Set("api_secret", strings.TrimSpace(config.ClientSecret))
	form.Set("from", from)
	form.Set("to", to)
	form.Set("text", text)
	if !isGsm(text) {
		form.Set("type", "unicode")
	}

	resp, err := sdk.Fetch(&sdk.Request{
		Method:  "POST",
		Url:     apiUrl,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
		Body:    []byte(form.Encode()),
	})
	if err != nil {
		return err
	}
	if resp.Status != 200 {
		return fmt.Errorf("Vonage returned HTTP %d: %s", resp.Status, resp.Body)
	}

	res := &smsResponse{}
	err = json.Unmarshal(resp.Body, res)
	if err != nil {
		return fmt.Errorf("Vonage returned an invalid response: %s", resp.Body)
	}
	if len(res.Messages) == 0 {
		return fmt.Errorf("Vonage returned no message: %s", resp.Body)
	}
	// a long text is sent as several messages, each with its own status
	for _, m := range res.Messages {
		if m.Status != "0" {
			return fmt.Errorf("Vonage did not send the message to +%s: %s (status %s)", to, m.ErrorText, m.Status)
		}
	}
	return nil
}

func (vonage) SendSms(config *sdk.Config, req *sdk.SendSmsReq) error {
	if strings.TrimSpace(config.ClientId) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return fmt.Errorf("fill in the Vonage API key as the client ID and the API secret as the client secret")
	}
	from := strings.TrimSpace(config.SignName)
	if from == "" {
		return fmt.Errorf("fill in the sign name with the sender: a Vonage number or an alphanumeric sender ID")
	}
	if len(req.PhoneNumbers) == 0 {
		return fmt.Errorf("no phone number to send to")
	}

	text, err := getText(config, req.Params)
	if err != nil {
		return err
	}

	for _, phoneNumber := range req.PhoneNumbers {
		to := strings.NewReplacer("+", "", " ", "", "-", "", "(", "", ")", "").Replace(phoneNumber)
		err = send(config, from, to, text)
		if err != nil {
			return err
		}
	}
	return nil
}

func init() {
	sdk.RegisterSms(vonage{})
}

func main() {}
