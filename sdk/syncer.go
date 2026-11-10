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

// SyncerUser is a user of the external system. Id is its stable ID there; the other fields map to the Casdoor user.
type SyncerUser struct {
	Id            string            `json:"id"`
	Name          string            `json:"name"`
	DisplayName   string            `json:"displayName"`
	Email         string            `json:"email"`
	EmailVerified bool              `json:"emailVerified"`
	Phone         string            `json:"phone"`
	CountryCode   string            `json:"countryCode"`
	Avatar        string            `json:"avatar"`
	Gender        string            `json:"gender"`
	Affiliation   string            `json:"affiliation"`
	Title         string            `json:"title"`
	IsForbidden   bool              `json:"isForbidden"`
	CreatedTime   string            `json:"createdTime"`
	Properties    map[string]string `json:"properties"`
	// the Ids of the SyncerGroups the user belongs to
	Groups []string `json:"groups"`
}

// SyncerGroup is a department of the external system. Id is its stable ID there, ParentId is empty for a top-level
// department.
type SyncerGroup struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	ParentId    string `json:"parentId"`
}

// UserSyncer is an action of kind "syncer", which imports the users of another identity system. The syncer's
// host, user and password fields arrive as config.Host, config.ClientId and config.ClientSecret.
type UserSyncer interface {
	ListUsers(config *Config) ([]*SyncerUser, error)
	TestConnection(config *Config) error
}

// GroupSyncer is a UserSyncer that also imports the department tree, which the users' Groups refer to.
type GroupSyncer interface {
	ListGroups(config *Config) ([]*SyncerGroup, error)
}

// RegisterSyncer makes the action a user syncer, and a group syncer too when syncer has ListGroups. Call it from init.
func RegisterSyncer(syncer UserSyncer) {
	handlers["syncer.listUsers"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		return syncer.ListUsers(config)
	}
	handlers["syncer.test"] = func(config *Config, params json.RawMessage) (interface{}, error) {
		return nil, syncer.TestConnection(config)
	}
	if groupSyncer, ok := syncer.(GroupSyncer); ok {
		handlers["syncer.listGroups"] = func(config *Config, params json.RawMessage) (interface{}, error) {
			return groupSyncer.ListGroups(config)
		}
	}
}
