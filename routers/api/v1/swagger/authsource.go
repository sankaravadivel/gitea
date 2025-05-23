// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package swagger

import (
	api "code.gitea.io/gitea/modules/structs"
)

// LDAPAuth
// swagger:response LDAPAuth
type swaggerResponseLdapAuth struct {
	// in:body
	Body api.LDAPAuth `json:"body"`
}
