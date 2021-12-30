package api

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/activities"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/signin"
)

// LoginEndpoint is an api handler used to login
func LoginEndpoint(c *gin.Context) {

	type Login struct {
		Password string `json:"password" binding:"required"`
		Email    string `json:"email" binding:"required"`
	}

	var data Login
	if err := c.BindJSON(&data); err != nil {
		log.Println(err)
		c.JSON(400, gin.H{
			"error":   true,
			"message": "Please pass password and email",
		})
		return
	}

	if !methods.ValidateEmail(data.Email) {
		// if there is some error passing bad status code
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Please enter valid email id."})
		return
	}

	// check request is from mobile or from somewhere else
	userAgent := c.Request.Header.Get("User-Agent")

	//=============================================
	// recording user activity
	activity := database.Activities{Email: data.Email,
		ClientIP:    c.ClientIP(),
		CreatedAt:   time.Now(),
		ClientAgent: userAgent,
		Timestamp:   time.Now().Unix()}
	//=============================================

	code, mapd := signin.SimpleSignin(strings.ToLower(data.Email), data.Password)
	if code == 200 {
		// recording user activity of login
		activity.ActivityName = "login"
		activity.CreatedAt = time.Now()
		activities.RecordActivity(activity)
	} else {
		// recording user activity of failed login
		activity.ActivityName = "failedlogin"
		activity.CreatedAt = time.Now()
		activities.RecordActivity(activity)
	}
	c.JSON(code, mapd)
}
