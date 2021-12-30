package api

import (
	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
)

// ChangePasswordEp is a api handler to change password of a account
func ChangePasswordEp(c *gin.Context) {

	// defining type for fetching password from body of post request
	type NewPassword struct {
		CurrentPassword string `json:"current_password" form:"current_password" binding:"required"`
		Password        string `json:"password" form:"password" binding:"required"`
	}
	var newPass NewPassword
	// binding body json with above variable and checking error

	err := c.BindJSON(&newPass)
	if err != nil {
		// if there is some error passing bad status code
		c.JSON(400, gin.H{"error": true, "message": "Password is required field."})
		return
	}

	//extracting jwt claims for getting user id

	claims := jwt.ExtractClaims(c)
	// passing new password and userid and in return getting status code, msg and error

	code, ok, msg := accounts.ChangePassword(claims["id"].(string), newPass.CurrentPassword, newPass.Password)

	c.JSON(code, gin.H{"error": !ok, "message": msg})
}

//=============================================================================
