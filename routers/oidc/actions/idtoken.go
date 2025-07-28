package actions

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"code.gitea.io/gitea/models/actions"
	"code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/services/context"
	"github.com/golang-jwt/jwt/v4"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/structs"

	"github.com/djherbis/times"
)

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
	Ref               string `json:"ref"`
}

type JWKSKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
	KID       string `json:"kid"`
	Algorithm string `json:"alg"`
}

type JWKSResp struct {
	Keys []JWKSKey `json:"keys"`
}

func GetIDToken(ctx *context.OIDCContext) {
	t, err := createToken(ctx)
	if err != nil {
		ctx.OIDCError(http.StatusInternalServerError, "failed to generate token")
		return
	}
	idt := structs.IDToken{
		Token: t,
	}
	ctx.JSON(http.StatusOK, idt)
}

func JWKS(ctx *context.OIDCContext) {
	entries, err := os.ReadDir(setting.OIDC.KeysFolderPath)
	if err != nil {
		ctx.OIDCError(http.StatusInternalServerError, fmt.Errorf("failed to get signing keys from the keys folder - %w", err))
		return
	}
	var keys []JWKSKey
	for _, e := range entries {
		if !e.IsDir() {
			privateKey, err := parseRSAPrivateKeyFromFile(filepath.Join(setting.OIDC.KeysFolderPath, e.Name()))
			if err != nil {
				log.Warn("failed to parse file %s - %v. Skipping...", e.Name(), err)
				continue
			}
			key, err := privateKeytoJWKSKey(privateKey)
			if err != nil {
				log.Warn("failed to generate JWSK object for file %s - %v. Skipping...", e.Name(), err)
				continue
			}
			keys = append(keys, *key)
		}
	}
	if len(keys) == 0 {
		ctx.OIDCError(http.StatusInternalServerError, "No signing keys found")
		return
	}
	ctx.JSON(http.StatusOK, JWKSResp{
		Keys: keys,
	})
}
func createToken(ctx *context.OIDCContext) (string, error) {

	signKey, err := getLatestPrivateKey(setting.OIDC.KeysFolderPath)
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

	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	rc := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
	}
	if setting.OIDC.Issuer != "" {
		rc.Issuer = setting.OIDC.Issuer
	}
	// Set the issuer to the OIDC issuer URL
	t.Claims = &OIDCClaims{
		RegisteredClaims:  rc,
		Subject:           fmt.Sprintf("repo:%s/%s", repo.OwnerName, repo.Name),
		Repository:        repo.Name,
		RepositoryOwner:   repo.OwnerName,
		RepositoryID:      repo.ID,
		RepositoryOwnerID: repo.OwnerID,
		RunID:             job.RunID,
		ActorID:           run.TriggerUserID,
		Actor:             triggerUser.Name,
		Ref:               run.Ref,
		EventName:         run.TriggerEvent,
	}

	// Create token string
	return t.SignedString(signKey)
}

// Always use the latest private key to sign the JWT token allowing for rotation of older keys
// This function gets the newest key based on last modified time which is not ideal. Wish the private keys
// has the creation time included in it
func getLatestPrivateKey(path string) (*rsa.PrivateKey, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keys from the keys folder - %w", err)
	}
	var newestFile fs.FileInfo
	var newestTime time.Time
	var privateKey *rsa.PrivateKey
	for _, entry := range entries {
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				// Log error but continue to process other files
				log.Warn("failed to get file info for %s: %v\n", entry.Name(), err)
				continue
			}
			keyPath := filepath.Join(setting.OIDC.KeysFolderPath, entry.Name())
			pk, err := parseRSAPrivateKeyFromFile(keyPath)
			if err != nil {
				log.Warn("not a private key %s: %v\n", entry.Name(), err)
				continue
			}
			birthTime := info.ModTime()
			t, err := times.Stat(keyPath)
			if err != nil {
				log.Warn("failed to get file time. Using FileInfo.ModTime - %v", err)
			} else {
				if t.HasBirthTime() {
					birthTime = t.BirthTime()
				} else {
					log.Warn("couldn't get the creation time of file %s. Using FileInfo.ModTime - %v", keyPath, err)
				}
			}

			if newestFile == nil || birthTime.After(newestTime) {
				newestTime = birthTime
				newestFile = info
				privateKey = pk
			}
		}
	}
	if privateKey == nil {
		return nil, fmt.Errorf("no signing key found")
	}
	log.Debug("The newest signing key is %s", newestFile.Name())
	return privateKey, nil
}

func parseRSAPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s - %v", path, err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid RSA private key - %v. skipping", path, err)
	}
	return privateKey, nil
}

func privateKeytoJWKSKey(privateKey *rsa.PrivateKey) (*JWKSKey, error) {
	verifyKey := privateKey.PublicKey
	modulus := verifyKey.N
	modulusBytes := modulus.Bytes()
	modulusBase64 := base64.RawURLEncoding.EncodeToString(modulusBytes)
	bigIntExponent := big.NewInt(int64(verifyKey.E))
	exponentBytes := bigIntExponent.Bytes()
	base64urlEncodedExponent := base64.RawURLEncoding.EncodeToString(exponentBytes)
	kid, err := generateKid(&verifyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwks - %v", err)
	}
	return &JWKSKey{
		KeyType:   "RSA",
		KID:       kid,
		Modulus:   modulusBase64,
		Exponent:  base64urlEncodedExponent,
		Algorithm: "RS256",
		Use:       "sig",
	}, nil
}

// kid is used to identify the specific public key within the JWKS that should be used
// to verify the token's signature.This allows for key rotation and multiple signing keys
// without requiring clients to download and store all possible public keys.
func generateKid(publicKey *rsa.PublicKey) (string, error) {
	// Marshal the public key to PKCS #1 format
	pubASN1 := x509.MarshalPKCS1PublicKey(publicKey)

	// Calculate SHA256 hash of the marshaled public key
	hash := sha256.Sum256(pubASN1)
	return hex.EncodeToString(hash[:]), nil
}
