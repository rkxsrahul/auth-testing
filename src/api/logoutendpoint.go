package api

import (
	"strings"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/jwtToken"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/redisdb"
	"github.com/gin-gonic/gin"
)

func Logout(c *gin.Context) {

	// fetch token from header

	token := c.Request.Header.Get("Authorization")
	// trim bearer from token
	token = strings.TrimPrefix(token, "Bearer ")
	// call delete token go function

	err := redisdb.DeleteToken(token)
	if err != nil {

		c.JSON(501, gin.H{
			"error":   err,
			"message": "Error in deleting token",
		})
	} else {
		// delete token from db means delete session from db
		go jwtToken.DeleteTokenFromDb(token)

		c.JSON(200, gin.H{
			"error":   false,
			"message": "Successfully logout",
		})
	}
}
