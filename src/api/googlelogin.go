package api

import (
	"github.com/gin-gonic/gin"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/sociallogin"
)

//GoogleLogin is used for the login with google
func GoogleLogin(c *gin.Context) {
	// fetch and set the redriect
	state := sociallogin.StateInformation{}

	//fetch the redirect url from url
	state.RedirectURL = c.Query("redirect")
	//fetch the token from url
	state.Token = c.Query("token")
	url := sociallogin.GoogleLogin(state)
	c.Redirect(302, url)
}

//GoogleCallback is an API handler for call back of google signin
func GoogleCallback(c *gin.Context) {
	// log.Println(c.Query("code"), c.Query("state"))
	code := c.Query("code")
	state := c.Query("state")

	url := sociallogin.GoogleCallback(code, state)
	c.Redirect(307, url)
}
