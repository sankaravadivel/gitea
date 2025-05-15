package structs

/*

var (
	commonLdapCLIFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "Authentication name.",
		},
		&cli.BoolFlag{
			Name:  "not-active",
			Usage: "Deactivate the authentication source.",
		},
		&cli.BoolFlag{
			Name:  "active",
			Usage: "Activate the authentication source.",
		},
		&cli.StringFlag{
			Name:  "security-protocol",
			Usage: "Security protocol name.",
		},
		&cli.BoolFlag{
			Name:  "skip-tls-verify",
			Usage: "Disable TLS verification.",
		},
		&cli.StringFlag{
			Name:  "host",
			Usage: "The address where the LDAP server can be reached.",
		},
		&cli.IntFlag{
			Name:  "port",
			Usage: "The port to use when connecting to the LDAP server.",
		},
		&cli.StringFlag{
			Name:  "user-search-base",
			Usage: "The LDAP base at which user accounts will be searched for.",
		},
		&cli.StringFlag{
			Name:  "user-filter",
			Usage: "An LDAP filter declaring how to find the user record that is attempting to authenticate.",
		},
		&cli.StringFlag{
			Name:  "admin-filter",
			Usage: "An LDAP filter specifying if a user should be given administrator privileges.",
		},
		&cli.StringFlag{
			Name:  "restricted-filter",
			Usage: "An LDAP filter specifying if a user should be given restricted status.",
		},
		&cli.BoolFlag{
			Name:  "allow-deactivate-all",
			Usage: "Allow empty search results to deactivate all users.",
		},
		&cli.StringFlag{
			Name:  "username-attribute",
			Usage: "The attribute of the user’s LDAP record containing the user name.",
		},
		&cli.StringFlag{
			Name:  "firstname-attribute",
			Usage: "The attribute of the user’s LDAP record containing the user’s first name.",
		},
		&cli.StringFlag{
			Name:  "surname-attribute",
			Usage: "The attribute of the user’s LDAP record containing the user’s surname.",
		},
		&cli.StringFlag{
			Name:  "email-attribute",
			Usage: "The attribute of the user’s LDAP record containing the user’s email address.",
		},
		&cli.StringFlag{
			Name:  "public-ssh-key-attribute",
			Usage: "The attribute of the user’s LDAP record containing the user’s public ssh key.",
		},
		&cli.BoolFlag{
			Name:  "skip-local-2fa",
			Usage: "Set to true to skip local 2fa for users authenticated by this source",
		},
		&cli.StringFlag{
			Name:  "avatar-attribute",
			Usage: "The attribute of the user’s LDAP record containing the user’s avatar.",
		},
	}

	ldapBindDnCLIFlags = append(commonLdapCLIFlags,
		&cli.StringFlag{
			Name:  "bind-dn",
			Usage: "The DN to bind to the LDAP server with when searching for the user.",
		},
		&cli.StringFlag{
			Name:  "bind-password",
			Usage: "The password for the Bind DN, if any.",
		},
		&cli.BoolFlag{
			Name:  "attributes-in-bind",
			Usage: "Fetch attributes in bind DN context.",
		},
		&cli.BoolFlag{
			Name:  "synchronize-users",
			Usage: "Enable user synchronization.",
		},
		&cli.BoolFlag{
			Name:  "disable-synchronize-users",
			Usage: "Disable user synchronization.",
		},
		&cli.UintFlag{
			Name:  "page-size",
			Usage: "Search page size.",
		},
		&cli.BoolFlag{
			Name:  "enable-groups",
			Usage: "Enable LDAP groups",
		},
		&cli.StringFlag{
			Name:  "group-search-base-dn",
			Usage: "The LDAP base DN at which group accounts will be searched for",
		},
		&cli.StringFlag{
			Name:  "group-member-attribute",
			Usage: "Group attribute containing list of users",
		},
		&cli.StringFlag{
			Name:  "group-user-attribute",
			Usage: "User attribute listed in group",
		},
		&cli.StringFlag{
			Name:  "group-filter",
			Usage: "Verify group membership in LDAP",
		},
		&cli.StringFlag{
			Name:  "group-team-map",
			Usage: "Map LDAP groups to Organization teams",
		},
		&cli.BoolFlag{
			Name:  "group-team-map-removal",
			Usage: "Remove users from synchronized teams if user does not belong to corresponding LDAP group",
		})

	ldapSimpleAuthCLIFlags = append(commonLdapCLIFlags,
		&cli.StringFlag{
			Name:  "user-dn",
			Usage: "The user's DN.",
		})

	microcmdAuthAddLdapBindDn = &cli.Command{
		Name:  "add-ldap",
		Usage: "Add new LDAP (via Bind DN) authentication source",
		Action: func(c *cli.Context) error {
			return newAuthService().addLdapBindDn(c)
		},
		Flags: ldapBindDnCLIFlags,
	}

	microcmdAuthUpdateLdapBindDn = &cli.Command{
		Name:  "update-ldap",
		Usage: "Update existing LDAP (via Bind DN) authentication source",
		Action: func(c *cli.Context) error {
			return newAuthService().updateLdapBindDn(c)
		},
		Flags: append([]cli.Flag{idFlag}, ldapBindDnCLIFlags...),
	}

	microcmdAuthAddLdapSimpleAuth = &cli.Command{
		Name:  "add-ldap-simple",
		Usage: "Add new LDAP (simple auth) authentication source",
		Action: func(c *cli.Context) error {
			return newAuthService().addLdapSimpleAuth(c)
		},
		Flags: ldapSimpleAuthCLIFlags,
	}

	microcmdAuthUpdateLdapSimpleAuth = &cli.Command{
		Name:  "update-ldap-simple",
		Usage: "Update existing LDAP (simple auth) authentication source",
		Action: func(c *cli.Context) error {
			return newAuthService().updateLdapSimpleAuth(c)
		},
		Flags: append([]cli.Flag{idFlag}, ldapSimpleAuthCLIFlags...),
	}
)
*/

type LDAPBind struct {
	BindDN               string `json:"bind_dn"`
	BindPassword         string `json:"bind_password"`
	AttributesInBind     string `json:"attributes_in_bind"`
	SyncUsers            bool   `json:"sync_users"`
	DisableSyncUsers     bool   `json:"disable_sync_users"`
	PageSize             int64  `json:"page_size"`
	EnableGroups         bool   `json:"enable_groups"`
	GroupSearchDN        string `json:"group_search_dn"`
	GroupMemberAttribute string `json:"group_member_attribute"`
	GroupUserAttribute   string `json:"group_user_attribute"`
	GroupFilter          string `json:"group_filter"`
	GroupTeamMap         string `json:"group_team_map"`
	GroupTeamMapRemoval  bool   `json:"group_team_map_removal"`
}

type LDAPAuth struct {
	Name                      string   `json:"name"`
	IsActive                  bool     `json:"is_active"`
	SecurityProtocol          string   `json:"security_protocol"`
	SkipVerifyTLS             bool     `json:"skip_verify_tls"`
	Host                      string   `json:"host"`
	Port                      int64    `json:"port"`
	UserSearchBase            string   `json:"user_search_base"`
	UserFilter                string   `json:"user_filter"`
	AdmingFilter              string   `json:"admin_filter"`
	RestrictedFilter          string   `json:"restricted_filter"`
	AllowDectivateAll         bool     `json:"allow_dectivate_all"`
	RepoAdminChangeTeamAccess bool     `json:"repo_admin_change_team_access"`
	UserNameAttribute         string   `json:"user_name_attribute"`
	FirstNameAttribute        string   `json:"first_name_attribute"`
	SurnameAttribute          string   `json:"surname_attribute"`
	EmailAttribute            string   `json:"email_attribute"`
	PublicSSHKeyAttribute     string   `json:"public_ssh_key_attribute"`
	SkipLocal2FA              bool     `json:"skip_local_2fa"`
	AvatarAttribute           string   `json:"avatar_attribute"`
	BindConfig                LDAPBind `json:"bind_config"`
}
