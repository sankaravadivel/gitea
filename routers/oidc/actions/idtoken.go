package actions

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"code.gitea.io/gitea/models/actions"
	"code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/user"
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
	ActorID           int64  `json:"actor_id"`
	Actor             string `json:"actor"`
}

type JWKSKey struct {
	KeyType               string   `json:"kty"`
	Use                   string   `json:"use"`
	Modulus               string   `json:"n"`
	Exponent              string   `json:"e"`
	KID                   string   `json:"kid"`
	Algorithm             string   `json:"alg"`
	CertificateChain      []string `json:"x5c"`
	CertificateThumbprint string   `json:"x5t"`
}

type JWKSResp struct {
	Keys []JWKSKey `json:"keys"`
}

func GetIDToken(ctx *context.OIDCContext) {
	t, err := createToken(ctx)
	if err != nil {
		ctx.OIDCError(http.StatusInternalServerError, "failed to generate token")
	}
	idt := structs.IDToken{
		Token: t,
	}
	ctx.JSON(http.StatusOK, idt)
}

func JWKS(ctx *context.OIDCContext) {
	privateKeyBytes, err := os.ReadFile(setting.OIDC.OIDCJWTPrivateKeyPath)
	if err != nil {
		ctx.OIDCError(http.StatusInternalServerError, fmt.Errorf("failed to read jwt verify key - %w", err))
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		ctx.OIDCError(http.StatusInternalServerError, fmt.Errorf("failed to parse jwt key - %w", err))
	}

	verifyKey := privateKey.PublicKey
	modulus := verifyKey.N
	modulusBytes := modulus.Bytes()
	modulusBase64 := base64.RawURLEncoding.EncodeToString(modulusBytes)
	bigIntExponent := big.NewInt(int64(verifyKey.E))
	exponentBytes := bigIntExponent.Bytes()
	base64urlEncodedExponent := base64.RawURLEncoding.EncodeToString(exponentBytes)
	jwksr := JWKSResp{
		Keys: []JWKSKey{
			{
				KeyType:   "RSA",
				KID:       "cc413527-173f-5a05-976e-9c52b1d7b431",
				Modulus:   modulusBase64,
				Exponent:  base64urlEncodedExponent,
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}
	ctx.JSON(http.StatusOK, jwksr)
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

	repo, err := repo.GetRepositoryByID(ctx, ctx.ActionsTask.RepoID)
	if err != nil {
		return "", fmt.Errorf("failed to get the repo attached to run - %w", err)
	}

	job, err := actions.GetRunJobByID(ctx, ctx.ActionsTask.JobID)
	if err != nil {
		return "", fmt.Errorf("failed to get the job details - %w", err)
	}

	run, err := actions.GetRunByID(ctx, job.RunID)
	if err != nil {
		return "", fmt.Errorf("failed to get run details - %w", err)
	}

	triggerUser, err := user.GetUserByID(ctx, run.TriggerUserID)
	if err != nil {
		return "", fmt.Errorf("failed to get actor details - %w", err)
	}

	t.Claims = &OIDCClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
		},
		Subject:           fmt.Sprintf("repo:%s/%s", repo.OwnerName, repo.Name),
		Repository:        repo.Name,
		RepositoryOwner:   repo.OwnerName,
		RepositoryID:      repo.ID,
		RepositoryOwnerID: repo.OwnerID,
		RunID:             job.RunID,
		ActorID:           run.TriggerUserID,
		Actor:             triggerUser.Name,
		//EventName:         run.E,
	}

	// Creat token string
	return t.SignedString(signKey)
}
