package auth

import (
	"fmt"
	"net/http"

	actions_model "code.gitea.io/gitea/models/actions"
	"code.gitea.io/gitea/services/actions"
)

type OIDCActionsAuth struct{}

func (oidc *OIDCActionsAuth) Verify(req *http.Request, w http.ResponseWriter, store DataStore, sess SessionStore) (*actions_model.ActionTask, error) {
	detector := newAuthPathDetector(req)
	if detector.isOIDCWellKnownPath() {
		return nil, nil
	}
	oa2 := OAuth2{}
	u, err := oa2.Verify(req, w, store, sess)
	if err != nil {
		return nil, err
	}
	if u.ID != -2 {
		return nil, fmt.Errorf("the provided actions-id-token-request-token is not valid")
	}
	token, ok := parseToken(req)
	if !ok {
		return nil, fmt.Errorf("no actions-id-token-request-token found in the auth header")
	}
	taskID, err := actions.TokenToTaskID(token)
	if err != nil || taskID == 0 {
		return nil, fmt.Errorf("actions-id-token-request-token did not contain a valid task")
	}
	task, err := actions_model.GetTaskByID(req.Context(), taskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get task by ID %d: %w", taskID, err)
	}
	return task, nil
}

func Name() string {
	return "actionsauth"
}
