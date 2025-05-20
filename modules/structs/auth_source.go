package structs

type LDAPBind struct {
	BindDN               string `json:"bind_dn"`
	BindPassword         string `json:"bind_password"`
	UserDN               string `json:"user_dn"`
	AttributesInBind     bool   `json:"attributes_in_bind"`
	SyncUsers            bool   `json:"sync_users"`
	DisableSyncUsers     bool   `json:"disable_sync_users"`
	PageSize             int    `json:"page_size"`
	EnableGroups         bool   `json:"enable_groups"`
	GroupSearchDN        string `json:"group_search_dn"`
	GroupMemberAttribute string `json:"group_member_attribute"`
	GroupUserAttribute   string `json:"group_user_attribute"`
	GroupFilter          string `json:"group_filter"`
	GroupTeamMap         string `json:"group_team_map"`
	GroupTeamMapRemoval  bool   `json:"group_team_map_removal"`
}

type LDAPAuth struct {
	ID                        int64    `json:"id"`
	Name                      string   `json:"name"`
	IsActive                  bool     `json:"is_active"`
	SecurityProtocol          string   `json:"security_protocol"`
	SkipVerifyTLS             bool     `json:"skip_verify_tls"`
	Host                      string   `json:"host"`
	Port                      int      `json:"port"`
	UserSearchBase            string   `json:"user_search_base"`
	UserFilter                string   `json:"user_filter"`
	AdminFilter               string   `json:"admin_filter"`
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
