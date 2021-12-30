package api

import (
	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/sociallogin"
	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
)

//GitHubLogin is an API handler
func GitHubLogin(c *gin.Context) {
	state := sociallogin.StateInformation{}
	state.RedirectURL = c.Query("redirect")
	//fetch the token from url
	state.Token = c.Query("token")
	url := sociallogin.GitHubLogin(state)
	c.Redirect(302, url)
}

//GitHubCallback is an API handler
func GitHubCallback(c *gin.Context) {
	// log.Println(c.Query("code"), c.Query("state"))
	code := c.Query("code")
	state := c.Query("state")

	url := sociallogin.GitHubCallback(code, state)
	c.Redirect(307, url)
}

//CheckIntegrations is an API handler for the check he integration information
func CheckIntegrations(c *gin.Context) {
	method := "github"
	if c.Query("method") != "" {
		method = c.Query("method")
	}

	//extract the token information
	claims := jwt.ExtractClaims(c)
	mapd, code := accounts.CheckIntegrations(claims["id"].(string), method)
	c.JSON(code, mapd)
}
