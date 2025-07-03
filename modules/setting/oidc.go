package setting

var OIDC = struct {
	EnableOIDC               bool
	OIDCJWTPubKeyPath        string
	OIDCJWTPrivateKeyPath    string
	ActionsIDTokenRequestURL string
	KeysFolderPath           string
}{}

func LoadOIDCSetting() {
	loadOIDCSetting(CfgProvider)
}

func loadOIDCSetting(rootCfg ConfigProvider) {
	sec := rootCfg.Section("oidc")
	OIDC.EnableOIDC = sec.Key("ENABLE_OIDC").MustBool(false)
	OIDC.ActionsIDTokenRequestURL = sec.Key("ACTIONS_ID_TOKEN_REQUEST_URL").String()
	OIDC.OIDCJWTPrivateKeyPath = sec.Key("JWT_PRIVATE_KEY_PATH").String()
	OIDC.KeysFolderPath = sec.Key("KEYS_FOLDER_PATH").String()
}
