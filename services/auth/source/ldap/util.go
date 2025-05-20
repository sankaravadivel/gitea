// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package ldap

import "strings"

// composeFullName composes a firstname surname or username
func composeFullName(firstname, surname, username string) string {
	switch {
	case firstname == "" && surname == "":
		return username
	case firstname == "":
		return surname
	case surname == "":
		return firstname
	default:
		return firstname + " " + surname
	}
}

func FindLdapSecurityProtocolByName(name string) (SecurityProtocol, bool) {
	for i, n := range SecurityProtocolNames {
		if strings.EqualFold(name, n) {
			return i, true
		}
	}
	return 0, false
}
