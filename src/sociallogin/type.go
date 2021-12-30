package sociallogin

//StateInformation is used to send and retrieve data using 3rd party integration
type StateInformation struct {
	RedirectURL string `json:"redirect_url"`
	Token       string `json:"token"`
}

type GoogleUserData struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
}

type GithubUserData struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

type GithubUserData2 struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}
