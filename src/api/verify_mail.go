package api

import (
	"net/http"
	"strings"
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/activities"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/jwtToken"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"

	"github.com/gin-gonic/gin"
)

// EmailVerifyToken defining structure for binding verification mail data
type EmailVerifyToken struct {
	VerificationCode string `json:"verification_code" binding:"required"`
	Email            string `json:"email" binding:"required"`
}

// VerifyMailEp is a api handler for verify email id by token
func VerifyMailEp(c *gin.Context) {
	// fetch opentracing span from context

	// binding request body data

	var tokendata EmailVerifyToken
	if c.BindJSON(&tokendata) != nil {

		// if there is some error passing bad status code
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Email and Verification Code are required field."})
		return
	}

	if !methods.ValidateEmail(tokendata.Email) {

		// if there is some error passing bad status code
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Please enter valid email id."})
		return
	}

	// passing email and token for getting verified

	account, ok := accounts.VerifyMail(strings.ToLower(tokendata.Email), tokendata.VerificationCode)
	if !ok {

		// if there is some error then passing StatusUnauthorized and msg invalid token
		c.JSON(http.StatusUnauthorized, gin.H{"error": true, "message": "Invalid or expired Verification Code."})
		return
	}

	//=============================================

	// saving user-activity
	activity := database.Activities{Email: tokendata.Email,
		ClientIP:     c.ClientIP(),
		ClientAgent:  c.Request.Header.Get("User-Agent"),
		Timestamp:    time.Now().Unix(),
		ActivityName: "email_verified"}
	activities.RecordActivity(activity)
	//=============================================

	// setting jwt token and claims to be used in other protected apis

	mapd := jwtToken.JwtToken(account)
	mapd["name"] = account.Name
	mapd["email"] = account.Email
	mapd["role_id"] = account.RoleID
	mapd["error"] = false
	mapd["message"] = "Email verification done"

	c.JSON(200, mapd)
}

// VerifyMailEp is a api handler for verify email id by token
func VerifyMail(c *gin.Context) {
	// fetch opentracing span from context

	// binding request body data

	var tokendata EmailVerifyToken
	if c.BindJSON(&tokendata) != nil {

		// if there is some error passing bad status code
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Email and Verification Code are required field."})
		return
	}

	if !methods.ValidateEmail(tokendata.Email) {

		// if there is some error passing bad status code
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Please enter valid email id."})
		return
	}

	// passing email and token for getting verified

	//=============================================

	//=============================================

	// setting jwt token and claims to be used in other protected apis

	mapd := make(map[string]interface{})

	mapd["token"] = "1234567890"
	mapd["name"] = "testing"
	mapd["email"] = "email"
	mapd["role_id"] = "user"
	mapd["error"] = false
	mapd["message"] = "Email verification done"

	c.JSON(200, mapd)
}
