package admin

import (
	"fmt"

	"code.gitea.io/gitea/models/auth"
	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/auth/source/ldap"
	"code.gitea.io/gitea/services/context"
)

func CreateLDAPAuthSource(ctx *context.APIContext) {
	// swagger:operation POST /admin/users/{username}/auths admin adminUpdateAuthSource
	// ---
	// summary: Create an organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: username
	//   in: path
	//   description: username of the user that will own the created organization
	//   type: string
	//   required: true
	// - name: organization
	//   in: body
	//   required: true
	//   schema: { "$ref": "#/definitions/CreateOrgOption" }
	// responses:
	//   "201":
	//     "$ref": "#/responses/Organization"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"
	form := *web.GetForm(ctx).(*api.LDAPAuth)
	print(form.Name)
	ctx.Data["Title"] = ctx.Tr("admin.auths.new")
	/* form := *web.GetForm(ctx).(*forms.AuthenticationForm)
	ctx.Data["Title"] = ctx.Tr("admin.auths.new")
	ctx.Data["PageIsAdminAuthentications"] = true

	ctx.Data["CurrentTypeName"] = auth.Type(form.Type).String()
	ctx.Data["CurrentSecurityProtocol"] = ldap.SecurityProtocolNames[ldap.SecurityProtocol(form.SecurityProtocol)]
	ctx.Data["AuthSources"] = authSources
	ctx.Data["SecurityProtocols"] = securityProtocols
	ctx.Data["SMTPAuths"] = smtp.Authenticators
	oauth2providers := oauth2.GetSupportedOAuth2Providers()
	ctx.Data["OAuth2Providers"] = oauth2providers

	ctx.Data["SSPIAutoCreateUsers"] = true
	ctx.Data["SSPIAutoActivateUsers"] = true
	ctx.Data["SSPIStripDomainNames"] = true
	ctx.Data["SSPISeparatorReplacement"] = "_"
	ctx.Data["SSPIDefaultLanguage"] = ""

	hasTLS := false
	var config auth.Config
	switch auth.Type(form.Type) {
	case auth.LDAP, auth.DLDAP:
		config = parseLDAPConfig(form)
		hasTLS = ldap.SecurityProtocol(form.SecurityProtocol) > ldap.SecurityProtocolUnencrypted
	case auth.SMTP:
		config = parseSMTPConfig(form)
		hasTLS = true
	case auth.PAM:
		config = &pam_service.Source{
			ServiceName: form.PAMServiceName,
			EmailDomain: form.PAMEmailDomain,
		}
	case auth.OAuth2:
		config = parseOAuth2Config(form)
		oauth2Config := config.(*oauth2.Source)
		if oauth2Config.Provider == "openidConnect" {
			discoveryURL, err := url.Parse(oauth2Config.OpenIDConnectAutoDiscoveryURL)
			if err != nil || (discoveryURL.Scheme != "http" && discoveryURL.Scheme != "https") {
				ctx.Data["Err_DiscoveryURL"] = true
				ctx.RenderWithErr(ctx.Tr("admin.auths.invalid_openIdConnectAutoDiscoveryURL"), tplAuthNew, form)
				return
			}
		}
	case auth.SSPI:
		var err error
		config, err = parseSSPIConfig(ctx, form)
		if err != nil {
			ctx.RenderWithErr(err.Error(), tplAuthNew, form)
			return
		}
		existing, err := db.Find[auth.Source](ctx, auth.FindSourcesOptions{LoginType: auth.SSPI})
		if err != nil || len(existing) > 0 {
			ctx.Data["Err_Type"] = true
			ctx.RenderWithErr(ctx.Tr("admin.auths.login_source_of_type_exist"), tplAuthNew, form)
			return
		}
	default:
		ctx.HTTPError(http.StatusBadRequest)
		return
	}
	ctx.Data["HasTLS"] = hasTLS

	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplAuthNew)
		return
	}

	if err := auth.CreateSource(ctx, &auth.Source{
		Type:            auth.Type(form.Type),
		Name:            form.Name,
		IsActive:        form.IsActive,
		IsSyncEnabled:   form.IsSyncEnabled,
		TwoFactorPolicy: form.TwoFactorPolicy,
		Cfg:             config,
	}); err != nil {
		if auth.IsErrSourceAlreadyExist(err) {
			ctx.Data["Err_Name"] = true
			ctx.RenderWithErr(ctx.Tr("admin.auths.login_source_exist", err.(auth.ErrSourceAlreadyExist).Name), tplAuthNew, form)
		} else if oauth2.IsErrOpenIDConnectInitialize(err) {
			ctx.Data["Err_DiscoveryURL"] = true
			unwrapped := err.(oauth2.ErrOpenIDConnectInitialize).Unwrap()
			ctx.RenderWithErr(ctx.Tr("admin.auths.unable_to_initialize_openid", unwrapped), tplAuthNew, form)
		} else {
			ctx.ServerError("auth.CreateSource", err)
		}
		return
	}

	log.Trace("Authentication created by admin(%s): %s", ctx.Doer.Name, form.Name)

	ctx.Flash.Success(ctx.Tr("admin.auths.new_success", form.Name))
	ctx.Redirect(setting.AppSubURL + "/-/admin/auths") */
}

func addLdapBindDn(ctx *context.APIContext) error {
	/*if err := argsSet(c, "name", "security-protocol", "host", "port", "user-search-base", "user-filter", "email-attribute"); err != nil {
		return err
	}*/

	authSource := &auth.Source{
		Type:     auth.LDAP,
		IsActive: true, // active by default
		Cfg: &ldap.Source{
			Enabled: true, // always true
		},
	}

	parseAuthSourceLdap(ctx, authSource)
	if err := parseLdapConfig(ctx, authSource.Cfg.(*ldap.Source)); err != nil {
		return err
	}

	return auth.CreateSource(ctx, authSource)
}
func parseAuthSourceLdap(form *api.LDAPAuth, authSource *auth.Source) {

	if form.Name != "" {
		authSource.Name = form.Name
	}
	authSource.IsActive = form.IsActive

	authSource.IsSyncEnabled = form.BindConfig.SyncUsers

	authSource.IsSyncEnabled = !form.BindConfig.DisableSyncUsers

	authSource.TwoFactorPolicy = util.Iif(form.SkipLocal2FA, "skip", "")
}

// parseLdapConfig assigns values on config according to command line flags.
func parseLdapConfig(form *api.LDAPAuth, config *ldap.Source) error {
	if c.IsSet("name") {
		config.Name = form.Name
	}
	if c.IsSet("host") {
		config.Host = form.Host
	}
	if c.IsSet("port") {
		config.Port = int(form.Port)
	}
	if c.IsSet("security-protocol") {
		p, ok := findLdapSecurityProtocolByName(c.String("security-protocol"))
		if !ok {
			return fmt.Errorf("Unknown security protocol name: %s", c.String("security-protocol"))
		}
		config.SecurityProtocol = p
	}
	if c.IsSet("skip-tls-verify") {
		config.SkipVerify = form.SkipVerifyTLS
	}
	if c.IsSet("bind-dn") {
		config.BindDN = form.BindConfig.BindDN
	}
	if c.IsSet("user-dn") {
		config.UserDN = form.
	}
	if c.IsSet("bind-password") {
		config.BindPassword = c.String("bind-password")
	}
	if c.IsSet("user-search-base") {
		config.UserBase = c.String("user-search-base")
	}
	if c.IsSet("username-attribute") {
		config.AttributeUsername = c.String("username-attribute")
	}
	if c.IsSet("firstname-attribute") {
		config.AttributeName = c.String("firstname-attribute")
	}
	if c.IsSet("surname-attribute") {
		config.AttributeSurname = c.String("surname-attribute")
	}
	if c.IsSet("email-attribute") {
		config.AttributeMail = c.String("email-attribute")
	}
	if c.IsSet("attributes-in-bind") {
		config.AttributesInBind = c.Bool("attributes-in-bind")
	}
	if c.IsSet("public-ssh-key-attribute") {
		config.AttributeSSHPublicKey = c.String("public-ssh-key-attribute")
	}
	if c.IsSet("avatar-attribute") {
		config.AttributeAvatar = c.String("avatar-attribute")
	}
	if c.IsSet("page-size") {
		config.SearchPageSize = uint32(c.Uint("page-size"))
	}
	if c.IsSet("user-filter") {
		config.Filter = c.String("user-filter")
	}
	if c.IsSet("admin-filter") {
		config.AdminFilter = c.String("admin-filter")
	}
	if c.IsSet("restricted-filter") {
		config.RestrictedFilter = c.String("restricted-filter")
	}
	if c.IsSet("allow-deactivate-all") {
		config.AllowDeactivateAll = c.Bool("allow-deactivate-all")
	}
	if c.IsSet("enable-groups") {
		config.GroupsEnabled = c.Bool("enable-groups")
	}
	if c.IsSet("group-search-base-dn") {
		config.GroupDN = c.String("group-search-base-dn")
	}
	if c.IsSet("group-member-attribute") {
		config.GroupMemberUID = c.String("group-member-attribute")
	}
	if c.IsSet("group-user-attribute") {
		config.UserUID = c.String("group-user-attribute")
	}
	if c.IsSet("group-filter") {
		config.GroupFilter = c.String("group-filter")
	}
	if c.IsSet("group-team-map") {
		config.GroupTeamMap = c.String("group-team-map")
	}
	if c.IsSet("group-team-map-removal") {
		config.GroupTeamMapRemoval = c.Bool("group-team-map-removal")
	}
	return nil
}
