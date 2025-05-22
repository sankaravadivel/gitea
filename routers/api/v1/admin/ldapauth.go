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
	"code.gitea.io/gitea/services/convert"
)

func CreateLDAPAuthSource(ctx *context.APIContext) {
	// swagger:operation POST /admin/auth/ldap admin adminCreateLdapAuthSource
	// ---
	// summary: Create a LDAP Authentication Source
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
	ctx.JSON(http.StatusCreated, convert.ToLdapAuth(authSource))
}

func UpdateLDAPAuthSource(ctx *context.APIContext) {
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
	ctx.JSON(http.StatusOK, convert.ToLdapAuth(authSource))
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
	ctx.JSON(http.StatusOK, convert.ToLdapAuth(source))
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
