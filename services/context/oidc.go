package context

import (
	"fmt"
	"net/http"

	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/cache"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/web"
	web_types "code.gitea.io/gitea/modules/web/types"
)

type OIDCContext struct {
	*Base

	Cache cache.StringCache

	Doer        *user_model.User // current signed-in user
	IsSigned    bool
	IsBasicAuth bool

	ContextUser *user_model.User // the user which is being visited, in most cases it differs from Doer

	Repo          *Repository
	Org           *APIOrganization
	Package       *Package
	PublicOnly    bool   // Whether the request is for a public endpoint
	IDToken       string // The ID Token for the OIDC request
	ISOIDCEnabled bool   // Whether the request is for a public endpoint
}

type OIDCAuthError struct {
	Message string `json:"message"`
	URL     string `json:"url"`
}

type OIDCInternalError struct {
	OIDCAuthError
}

type oidcContextKeyType struct{}

var oidcContextKey = oidcContextKeyType{}

func init() {
	web.RegisterResponseStatusProvider[*OIDCContext](func(req *http.Request) web_types.ResponseStatusProvider {
		return req.Context().Value(oidcContextKey).(*OIDCContext)
	})
}

func OIDCContexter() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			base := NewBaseContext(w, req)
			ctx := &OIDCContext{
				Base: base,
			}

			ctx.SetContextValue(oidcContextKey, ctx)

			next.ServeHTTP(ctx.Resp, ctx.Req)
		})
	}
}

func (ctx *OIDCContext) OIDCError(status int, obj any) {
	var message string
	if err, ok := obj.(error); ok {
		message = err.Error()
	} else {
		message = fmt.Sprintf("%s", obj)
	}

	if status == http.StatusInternalServerError {
		log.ErrorWithSkip(1, "APIError: %s", message)

	}

	ctx.JSON(status, OIDCAuthError{
		Message: message,
		URL:     setting.API.SwaggerURL,
	})
}
