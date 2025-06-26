package actions

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"code.gitea.io/gitea/services/context"
	"github.com/golang-jwt/jwt/v4"

	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/structs"
)

/*
*

	"jti": "example-id",
	"sub": "repo:octo-org/octo-repo:environment:prod",
	"environment": "prod",
	"aud": "https://github.com/octo-org",
	"ref": "refs/heads/main",
	"sha": "example-sha",
	"repository": "octo-org/octo-repo",
	"repository_owner": "octo-org",
	"actor_id": "12",
	"repository_visibility": "private",
	"repository_id": "74",
	"repository_owner_id": "65",
	"run_id": "example-run-id",
	"run_number": "10",
	"run_attempt": "2",
	"runner_environment": "github-hosted",
	"actor": "octocat",
	"workflow": "example-workflow",
	"head_ref": "",
	"base_ref": "",
	"event_name": "workflow_dispatch",
	"ref_type": "branch",
	"job_workflow_ref": "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main",
	"iss": "https://token.actions.githubusercontent.com",
	"nbf": 1632492967,
	"exp": 1632493867,
	"iat": 1632493567

*
*/
type OIDCClaims struct {
	jwt.RegisteredClaims
	Subject           string `json:"sub"`
	Repository        string `json:"repository"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryID      int64  `json:"repository_id"`
	RepositoryOwnerID int64  `json:"repository_owner_id"`
	RunID             int64  `json:"run_id"`
	EventName         string `json:"event_name"`
}

func GetIDToken(ctx *context.OIDCContext) {
	t, err := createToken(ctx)
	if err != nil {
		ctx.OIDCError(http.StatusInternalServerError, "failed to generate token")
	}
	idt := structs.IDToken{
		Token: t,
	}
	ctx.JSON(http.StatusCreated, idt)
}

func createToken(ctx *context.OIDCContext) (string, error) {
	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	signBytes, err := os.ReadFile(setting.OIDC.OIDCJWTPrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read jwt signing key - %w", err)
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return "", fmt.Errorf("invalid jwt signing key file - %w", err)
	}

	t.Claims = &OIDCClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
		},
		Subject:           fmt.Sprintf("repo:%s", ctx.ActionsTask.GetRepoName()),
		Repository:        ctx.ActionsTask.Job.Repo.Name,
		RepositoryOwner:   ctx.ActionsTask.Job.Repo.OwnerName,
		RepositoryID:      ctx.ActionsTask.Job.RepoID,
		RepositoryOwnerID: ctx.ActionsTask.Job.Repo.OwnerID,
		RunID:             ctx.ActionsTask.Job.RunID,
		EventName:         ctx.ActionsTask.Job.Run.Event.Event(),
	}

	// Creat token string
	return t.SignedString(signKey)
}
