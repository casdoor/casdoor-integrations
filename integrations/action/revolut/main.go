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

// Revolut accepts payments through the Revolut Merchant API: Pay creates an order and sends the payer to its
// hosted checkout page, Notify reads the order back from Revolut.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strings"

	"github.com/casdoor/casdoor-integrations/sdk"
)

const apiVersion = "2026-08-17"

// currencies whose minor unit is not a hundredth (ISO 4217); Revolut takes amounts in minor units
var currencyExponents = map[string]int{
	"BIF": 0, "CLP": 0, "DJF": 0, "GNF": 0, "ISK": 0, "JPY": 0, "KMF": 0, "KRW": 0, "PYG": 0,
	"RWF": 0, "UGX": 0, "VND": 0, "VUV": 0, "XAF": 0, "XOF": 0, "XPF": 0,
	"BHD": 3, "IQD": 3, "JOD": 3, "KWD": 3, "LYD": 3, "OMR": 3, "TND": 3,
}

type revolut struct{}

type order struct {
	Id          string            `json:"id"`
	State       string            `json:"state"`
	Amount      int64             `json:"amount"`
	Currency    string            `json:"currency"`
	CheckoutUrl string            `json:"checkout_url"`
	Metadata    map[string]string `json:"metadata"`
}

func getBaseUrl(config *sdk.Config) (string, error) {
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(config.Host), "https://"), "/")
	switch host {
	case "", "merchant.revolut.com":
		return "https://merchant.revolut.com/api", nil
	case "sandbox", "sandbox-merchant.revolut.com":
		return "https://sandbox-merchant.revolut.com/api", nil
	default:
		return "", fmt.Errorf("the host must be merchant.revolut.com or sandbox-merchant.revolut.com, not %s", config.Host)
	}
}

func getScale(currency string) float64 {
	exponent, ok := currencyExponents[currency]
	if !ok {
		exponent = 2
	}
	return math.Pow10(exponent)
}

// Revolut refuses a redirect URL on localhost or an IP address, so a Casdoor tried out locally leaves the payer on
// Revolut's page after paying
func isRedirectAllowed(redirectUrl string) bool {
	u, err := url.Parse(redirectUrl)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	host := u.Hostname()
	return host != "localhost" && !strings.HasSuffix(host, ".localhost") && !isIp(host)
}

func isIp(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

func request(config *sdk.Config, method string, path string, body interface{}, out interface{}) error {
	baseUrl, err := getBaseUrl(config)
	if err != nil {
		return err
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("the secret key of the Revolut provider is empty")
	}

	var data []byte
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}

	resp, err := sdk.Fetch(&sdk.Request{
		Method: method,
		Url:    baseUrl + path,
		Headers: map[string]string{
			"Authorization":       "Bearer " + config.ClientSecret,
			"Revolut-Api-Version": apiVersion,
			"Content-Type":        "application/json",
			"Accept":              "application/json",
		},
		Body: data,
	})
	if err != nil {
		return err
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return fmt.Errorf("revolut returned %d: %s", resp.Status, strings.TrimSpace(string(resp.Body)))
	}
	return json.Unmarshal(resp.Body, out)
}

func (revolut) Pay(config *sdk.Config, req *sdk.PayReq) (*sdk.PayResp, error) {
	currency := strings.ToUpper(req.Currency)
	if currency == "" {
		currency = "USD"
	}

	description := req.ProductDisplayName
	if description == "" {
		description = req.ProductName
	}

	body := map[string]interface{}{
		"amount":      int64(math.Round(req.Price * getScale(currency))),
		"currency":    currency,
		"description": description,
		"merchant_order_data": map[string]string{
			"reference": req.PaymentName,
		},
		"metadata": map[string]string{
			"payment_name":         req.PaymentName,
			"product_name":         req.ProductName,
			"product_display_name": req.ProductDisplayName,
			"provider_name":        req.ProviderName,
		},
	}
	if req.PayerEmail != "" {
		body["customer"] = map[string]string{"email": req.PayerEmail}
	}
	if isRedirectAllowed(req.ReturnUrl) {
		body["redirect_url"] = req.ReturnUrl
	}

	o := &order{}
	err := request(config, "POST", "/orders", body, o)
	if err != nil {
		return nil, err
	}
	if o.Id == "" || o.CheckoutUrl == "" {
		return nil, fmt.Errorf("revolut created no checkout page for the order")
	}

	return &sdk.PayResp{PayUrl: o.CheckoutUrl, OrderId: o.Id}, nil
}

func (revolut) Notify(config *sdk.Config, req *sdk.NotifyReq) (*sdk.NotifyResult, error) {
	if req.OrderId == "" {
		return nil, fmt.Errorf("the payment has no Revolut order")
	}

	o := &order{}
	err := request(config, "GET", "/orders/"+url.PathEscape(req.OrderId), nil, o)
	if err != nil {
		return nil, err
	}

	switch o.State {
	case "completed":
	case "pending", "processing", "authorised":
		return &sdk.NotifyResult{PaymentStatus: sdk.PaymentStateCreated}, nil
	case "cancelled":
		return &sdk.NotifyResult{PaymentStatus: sdk.PaymentStateCanceled}, nil
	case "failed":
		return &sdk.NotifyResult{PaymentStatus: sdk.PaymentStateError, NotifyMessage: "the Revolut order failed or expired"}, nil
	default:
		return &sdk.NotifyResult{PaymentStatus: sdk.PaymentStateError, NotifyMessage: fmt.Sprintf("unexpected Revolut order state: %s", o.State)}, nil
	}

	currency := strings.ToUpper(o.Currency)
	return &sdk.NotifyResult{
		PaymentName:   o.Metadata["payment_name"],
		PaymentStatus: sdk.PaymentStatePaid,

		ProductName:        o.Metadata["product_name"],
		ProductDisplayName: o.Metadata["product_display_name"],
		ProviderName:       o.Metadata["provider_name"],
		Price:              float64(o.Amount) / getScale(currency),
		Currency:           currency,

		OrderId: o.Id,
	}, nil
}

func init() {
	sdk.RegisterPayment(revolut{})
}

func main() {}
