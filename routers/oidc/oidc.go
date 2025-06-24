package oidc

import (
	"net/http"

	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/routers/common"
	"code.gitea.io/gitea/routers/oidc/actions"
	"code.gitea.io/gitea/services/auth"
	"code.gitea.io/gitea/services/context"
)

func buildAuthGroup() *auth.Group {
	group := auth.NewGroup(
		&auth.OAuth2{},
		&auth.HTTPSign{},
		&auth.Basic{}, // FIXME: this should be removed once we don't allow basic auth in API
	)
	return group
}

func Routes() *web.Router {
	m := web.NewRouter()
	m.Use(context.OIDCContexter())
	m.Use(oidcAuth(buildAuthGroup()))
	m.Get("/id-token", actions.GetIDToken)
	return m
}

func oidcAuth(authMethod auth.Method) func(*context.OIDCContext) {
	return func(ctx *context.OIDCContext) {
		ar, err := common.AuthShared(ctx.Base, nil, authMethod)
		if err != nil {
			ctx.OIDCError(http.StatusUnauthorized, err)
			return
		}
		ctx.Doer = ar.Doer
		ctx.IsSigned = ar.Doer != nil
		ctx.IsBasicAuth = ar.IsBasicAuth
	}
}
