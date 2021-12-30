package api

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/activities"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/forgotpass"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
)

// ForgotPassData is a  structure for binding data in body during forget or reset password request
type ForgotPassData struct {
	// state defines the state of request is it forgot or reset
	State string `json:"state" binding:"required"`
	// email of user
	Email string `json:"email"`
	// token recieved in email for resetting password
	Token string `json:"token"`
	// new password
	Password string `json:"password"`
}

// ForgotPassEp is an api handler for forgot and reset password
func ForgotPassEp(c *gin.Context) {

	var fpdt ForgotPassData
	if err := c.BindJSON(&fpdt); err != nil {
		// if there is some error passing bad status code
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "State field is missing."})
		return
	}

	// when state is forget email is passed
	if fpdt.State == "forgot" {

		if !methods.ValidateEmail(fpdt.Email) {
			// if there is some error passing bad status code
			c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Please enter valid email id."})
			return
		}

		msg, ok := forgotpass.ForgotPass(strings.ToLower(fpdt.Email))
		// return status code and msg and error if any
		c.JSON(http.StatusOK, gin.H{"error": !(ok), "message": msg})
		return
	}
	// when state is reset token and new password is passed
	if fpdt.State == "reset" {
		email, msg, ok := forgotpass.ResetForgottenPassword(fpdt.Token, fpdt.Password)
		if ok {
			// recording user activity of reseting password
			activities.RecordActivity(database.Activities{Email: email,
				ActivityName: "reset_password",
				ClientIP:     c.ClientIP(),
				ClientAgent:  c.Request.Header.Get("User-Agent"),
				Timestamp:    time.Now().Unix()})

			// return status code and msg and error if any
			c.JSON(http.StatusOK, gin.H{"error": !(ok), "message": msg})
			return
		}
		// return status code and msg and error if any
		c.JSON(http.StatusBadRequest, gin.H{"error": !(ok), "message": msg})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "State field value should be forgot or reset only."})
}
