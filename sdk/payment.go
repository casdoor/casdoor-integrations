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

// The states a payment can be in, the same as Casdoor's pp.PaymentState.
const (
	PaymentStatePaid     = "Paid"
	PaymentStateCreated  = "Created"
	PaymentStateCanceled = "Canceled"
	PaymentStateTimeout  = "Timeout"
	PaymentStateError    = "Error"
)

type PayReq struct {
	ProviderName       string  `json:"providerName"`
	ProductName        string  `json:"productName"`
	PayerName          string  `json:"payerName"`
	PayerId            string  `json:"payerId"`
	PayerEmail         string  `json:"payerEmail"`
	PaymentName        string  `json:"paymentName"`
	ProductDisplayName string  `json:"productDisplayName"`
	ProductDescription string  `json:"productDescription"`
	ProductImage       string  `json:"productImage"`
	Price              float64 `json:"price"`
	Currency           string  `json:"currency"`

	// where the payer comes back to after paying, and where the payment service can tell Casdoor about the payment
	ReturnUrl string `json:"returnUrl"`
	NotifyUrl string `json:"notifyUrl"`

	PaymentEnv string `json:"paymentEnv"`
}

type PayResp struct {
	PayUrl     string                 `json:"payUrl"`
	OrderId    string                 `json:"orderId"`
	AttachInfo map[string]interface{} `json:"attachInfo,omitempty"`
}

type NotifyReq struct {
	Body    []byte `json:"body"`
	OrderId string `json:"orderId"`
}

type NotifyResult struct {
	PaymentName   string `json:"paymentName"`
	PaymentStatus string `json:"paymentStatus"`
	NotifyMessage string `json:"notifyMessage"`

	ProductName        string  `json:"productName"`
	ProductDisplayName string  `json:"productDisplayName"`
	ProviderName       string  `json:"providerName"`
	Price              float64 `json:"price"`
	Currency           string  `json:"currency"`

	OrderId string `json:"orderId"`
}

// PaymentProvider is a payment service. Notify is called when the payer comes back or the service calls the
// notify URL; it should ask the service for the state of the order rather than trust the body.
type PaymentProvider interface {
	Pay(config *Config, req *PayReq) (*PayResp, error)
	Notify(config *Config, req *NotifyReq) (*NotifyResult, error)
}

// RegisterPayment makes the action a payment provider. Call it from init.
func RegisterPayment(provider PaymentProvider) {
	handlers["payment.pay"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &PayReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return provider.Pay(config, req)
	}
	handlers["payment.notify"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		req := &NotifyReq{}
		err := json.Unmarshal(params, req)
		if err != nil {
			return nil, err
		}
		return provider.Notify(config, req)
	}
}
