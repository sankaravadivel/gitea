package admin

import (
	"fmt"
	"net/http"

	"code.gitea.io/gitea/models/auth"
	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/auth/source/ldap"
	"code.gitea.io/gitea/services/context"
)

func CreateLDAPAuthSource(ctx *context.APIContext) {
	// swagger:operation POST /admin/auth/ldap admin adminCreateLdapAuthSource
	// ---
	// summary: Create a new LDAP Authentication Source
	// description: Creates a new LDAP authentication source with the provided configuration.
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: ldap_auth
	//   in: body
	//   description: The LDAP authentication source configuration to create
	//   required: true
	//   schema:
	//     $ref: "#/definitions/LDAPAuth"
	// responses:
	//   "201":
	//     description: LDAP authentication source created successfully
	//     schema:
	//       $ref: "#/definitions/LDAPAuth"
	//   "400":
	//     description: Invalid request or validation error
	//   "422":
	//     description: LDAP authentication source already exists or unprocessable entity
	//   "500":
	//     description: Internal server error

	form := web.GetForm(ctx).(*api.LDAPAuth)
	ctx.Data["Title"] = ctx.Tr("admin.auths.new")
	authSource := &auth.Source{
		Type:     auth.LDAP,
		IsActive: true, // active by default
		Cfg: &ldap.Source{
			Enabled: true, // always true
		},
	}

	parseAuthSourceConfig(form, authSource)
	if err := parseLdapConfig(form, authSource.Cfg.(*ldap.Source)); err != nil {
		ctx.APIError(http.StatusUnprocessableEntity, err)
	}

	err := auth.CreateSource(ctx, authSource)
	if err != nil {
		if auth.IsErrSourceAlreadyExist(err) {
			ctx.APIError(http.StatusUnprocessableEntity, err)
		}
		ctx.APIErrorInternal(err)
	}
	form.ID = authSource.ID
	a, err := toLdapAuth(authSource)
	if err != nil {
		ctx.APIError(http.StatusInternalServerError, err)
	}
	ctx.JSON(http.StatusCreated, a)
}

func UpdateLDAPAuthSource(ctx *context.APIContext) {
	// swagger:operation PATCH /admin/auth/ldap/{id} admin adminUpdateLdapAuthSource
	// ---
	// summary: Update an LDAP Authentication Source
	// description: Updates the configuration of an existing LDAP authentication source by its ID.
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: ID of the LDAP Authentication Source to update
	//   required: true
	//   type: integer
	// - name: ldap_auth
	//   in: body
	//   description: The updated LDAP authentication source configuration
	//   required: true
	//   schema:
	//     $ref: "#/definitions/LDAPAuth"
	// responses:
	//   "200":
	//     description: LDAP authentication source updated successfully
	//     schema:
	//       $ref: "#/definitions/LDAPAuth"
	//   "400":
	//     description: Invalid request or validation error
	//   "404":
	//     description: LDAP authentication source not found
	//   "500":
	//     description: Internal server error

	form := web.GetForm(ctx).(*api.LDAPAuth)
	form.ID = ctx.PathParamInt64("id")
	ctx.Data["Title"] = ctx.Tr("admin.auths.new")
	authSource := &auth.Source{
		ID:       form.ID,
		Type:     auth.LDAP,
		IsActive: true, // active by default
		Cfg: &ldap.Source{
			Enabled: true, // always true
		},
	}

	parseAuthSourceConfig(form, authSource)
	if err := parseLdapConfig(form, authSource.Cfg.(*ldap.Source)); err != nil {
		ctx.APIError(http.StatusUnprocessableEntity, err)
	}
	err := auth.UpdateSource(ctx, authSource)
	if err != nil {
		if auth.IsErrSourceAlreadyExist(err) {
			ctx.APIError(http.StatusUnprocessableEntity, err)
		}
		ctx.APIErrorInternal(err)
	}
	a, err := toLdapAuth(authSource)
	if err != nil {
		ctx.APIError(http.StatusInternalServerError, err)
	}
	ctx.JSON(http.StatusOK, a)
}

func GetLDAPAuthSource(ctx *context.APIContext) {
	id := ctx.PathParamInt64("id")
	source, err := auth.GetSourceByID(ctx, id)
	if err != nil {
		if auth.IsErrSourceNotExist(err) {
			ctx.APIError(http.StatusUnprocessableEntity, err)
		}
		ctx.APIErrorInternal(err)
	}
	a, err := toLdapAuth(source)
	if err != nil {
		ctx.APIError(http.StatusInternalServerError, err)
	}
	ctx.JSON(http.StatusOK, a)
}

func parseAuthSourceConfig(form *api.LDAPAuth, authSource *auth.Source) {

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
	config.Name = form.Name
	config.Host = form.Host
	config.Port = form.Port

	if form.SecurityProtocol != "" {
		p, ok := ldap.FindLdapSecurityProtocolByName(form.SecurityProtocol)
		if !ok {
			return fmt.Errorf("unknown security protocol name: %s", form.SecurityProtocol)
		}
		config.SecurityProtocol = p
	}
	config.SkipVerify = form.SkipVerifyTLS
	config.BindDN = form.BindConfig.BindDN
	config.UserDN = form.BindConfig.UserDN
	config.BindPassword = form.BindConfig.BindPassword
	config.UserBase = form.UserSearchBase
	config.AttributeUsername = form.UserNameAttribute
	config.AttributeName = form.FirstNameAttribute
	config.AttributeSurname = form.SurnameAttribute
	config.AttributeMail = form.EmailAttribute
	config.AttributesInBind = form.BindConfig.AttributesInBind
	config.AttributeSSHPublicKey = form.PublicSSHKeyAttribute
	config.AttributeAvatar = form.AvatarAttribute
	config.SearchPageSize = uint32(form.BindConfig.PageSize)
	config.Filter = form.UserFilter
	config.AdminFilter = form.AdminFilter
	config.RestrictedFilter = form.RestrictedFilter
	config.AllowDeactivateAll = form.AllowDectivateAll
	config.GroupsEnabled = form.BindConfig.EnableGroups
	config.GroupDN = form.BindConfig.GroupSearchDN
	config.GroupMemberUID = form.BindConfig.GroupMemberAttribute
	config.UserUID = form.BindConfig.GroupUserAttribute
	config.GroupFilter = form.BindConfig.GroupFilter
	config.GroupTeamMap = form.BindConfig.GroupTeamMap
	config.GroupTeamMapRemoval = form.BindConfig.GroupTeamMapRemoval
	return nil
}

func toLdapAuth(source *auth.Source) (*api.LDAPAuth, error) {
	ldapSource, ok := source.Cfg.(*ldap.Source)
	if !ok {
		return nil, fmt.Errorf("source config is not ldap")
	}
	form := &api.LDAPAuth{
		ID:                    source.ID,
		Name:                  source.Name,
		IsActive:              source.IsActive,
		UserSearchBase:        ldapSource.UserBase,
		UserNameAttribute:     ldapSource.AttributeUsername,
		FirstNameAttribute:    ldapSource.AttributeName,
		SurnameAttribute:      ldapSource.AttributeSurname,
		EmailAttribute:        ldapSource.AttributeMail,
		PublicSSHKeyAttribute: ldapSource.AttributeSSHPublicKey,
		AvatarAttribute:       ldapSource.AttributeAvatar,
		UserFilter:            ldapSource.Filter,
		SecurityProtocol:      ldapSource.SecurityProtocolName(),
		BindConfig: api.LDAPBind{
			GroupSearchDN:        ldapSource.GroupDN,
			GroupMemberAttribute: ldapSource.GroupMemberUID,
			GroupUserAttribute:   ldapSource.UserUID,
			GroupFilter:          ldapSource.GroupFilter,
			GroupTeamMap:         ldapSource.GroupTeamMap,
			GroupTeamMapRemoval:  ldapSource.GroupTeamMapRemoval,
			BindDN:               ldapSource.BindDN,
			BindPassword:         ldapSource.BindPassword,
			UserDN:               ldapSource.UserDN,
			AttributesInBind:     ldapSource.AttributesInBind,
			SyncUsers:            source.IsSyncEnabled,
			DisableSyncUsers:     !source.IsSyncEnabled,
			PageSize:             int(ldapSource.SearchPageSize),
			EnableGroups:         ldapSource.GroupsEnabled,
		},
	}
	return form, nil
}
