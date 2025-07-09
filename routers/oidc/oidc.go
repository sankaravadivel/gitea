package oidc

import (
	"net/http"

	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/routers/oidc/actions"
	"code.gitea.io/gitea/services/auth"
	"code.gitea.io/gitea/services/context"
)

func Routes() *web.Router {
	m := web.NewRouter()
	m.Use(context.OIDCContexter())
	m.Use(oidcAuth())
	m.Get("/id-token", actions.GetIDToken)
	m.Get("/id", actions.GetIDToken)
	m.Get("/.well-known/jwks", actions.JWKS)
	return m
}

func oidcAuth() func(*context.OIDCContext) {
	return func(ctx *context.OIDCContext) {
		oidc := auth.OIDCActionsAuth{}
		at, err := oidc.Verify(ctx.Req, ctx.Resp, ctx, nil)
		if err != nil {
			ctx.OIDCError(http.StatusUnauthorized, err)
			return
		}
		ctx.ActionsTask = at
	}
}
