package actions

import (
	"net/http"

	"code.gitea.io/gitea/services/context"

	"code.gitea.io/gitea/modules/structs"
)

func GetIDToken(ctx *context.OIDCContext) {
	idt := structs.IDToken{
		Token: "hello world",
	}
	ctx.JSON(http.StatusCreated, idt)
}
