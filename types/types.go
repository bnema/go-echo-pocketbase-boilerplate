package types

type OAuthProvider struct {
	Provider string `json:"provider"`
}

type AuthMethodsResponse struct {
	AuthProviders []struct {
		Name         string `json:"name"`
		State        string `json:"state"`
		CodeVerifier string `json:"codeVerifier"`
		AuthURL      string `json:"authUrl"`
	}
}

type OAuthRequest struct {
	Provider     string `json:"provider"`
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURL  string `json:"redirectUrl"`
	State        string `json:"state"`
}

type TradeResponse struct {
	Token  string `json:"token"`
	Record struct {
		Id              string `json:"id"`
		CollectionId    string `json:"collectionId"`
		CollectionName  string `json:"collectionName"`
		Username        string `json:"username"`
		Verified        bool   `json:"verified"`
		EmailVisibility bool   `json:"emailVisibility"`
		Email           string `json:"email"`
		Created         string `json:"created"`
		Updated         string `json:"updated"`
		Name            string `json:"name"`
		Avatar          string `json:"avatar"`
	} `json:"record"`
	Meta struct {
		Id           string `json:"id"`
		Name         string `json:"name"`
		Username     string `json:"username"`
		Email        string `json:"email"`
		AvatarUrl    string `json:"avatarUrl"`
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		RawUser      struct {
		} `json:"rawUser"`
	} `json:"meta"`
}

type RefreshResponse struct {
	Token  string `json:"token"`
	Record struct {
		Id              string `json:"id"`
		CollectionId    string `json:"collectionId"`
		CollectionName  string `json:"collectionName"`
		Username        string `json:"username"`
		Verified        bool   `json:"verified"`
		EmailVisibility bool   `json:"emailVisibility"`
		Email           string `json:"email"`
		Created         string `json:"created"`
		Updated         string `json:"updated"`
		Name            string `json:"name"`
		Avatar          string `json:"avatar"`
	} `json:"record"`
}

type OAuthResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type PocketBaseUser struct {
	Token  string               `json:"token"`
	Record PocketBaseUserRecord `json:"record"`
	Meta   PocketBaseUserMeta   `json:"meta"`
}

type PocketBaseUserRecord struct {
	Id              string `json:"id"`
	CollectionId    string `json:"collectionId"`
	CollectionName  string `json:"collectionName"`
	Username        string `json:"username"`
	Verified        bool   `json:"verified"`
	EmailVisibility bool   `json:"emailVisibility"`
	Email           string `json:"email"`
	Created         string `json:"created"`
	Updated         string `json:"updated"`
	Name            string `json:"name"`
	Avatar          string `json:"avatar"`
}

type PocketBaseUserMeta struct {
	Id           string `json:"id"`
	Name         string `json:"name"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	AvatarUrl    string `json:"avatarUrl"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	RawUser      string `json:"rawUser"`
}
