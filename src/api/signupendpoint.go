package api

import (
	"net/http"
	"strings"
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/signup"

	"github.com/gin-gonic/gin"
)

// SignupData defining structure for binding signup data
type SignupData struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Name      string `json:"name"`
	Contact   string `json:"contact"`
	Email     string `json:"email" binding:"required"`
	Password  string `json:"password" binding:"required"`
}

// SignupEndpoint is a api handler for creating accounts
func SignupEndpoint(c *gin.Context) {

	// binding body data

	var signupdt SignupData
	if err := c.BindJSON(&signupdt); err != nil {

		// if there is some error passing bad status code
		c.JSON(400, gin.H{"error": true, "message": "email, password and name are required fields."})
		return
	}

	//saving data in account structure
	acs := database.Accounts{}
	acs.Name = signupdt.FirstName + " " + signupdt.LastName
	//validation check on email

	if !methods.ValidateEmail(strings.ToLower(signupdt.Email)) {

		c.JSON(400, gin.H{"error": true, "message": "Please pass valid email address"})
		return
	}
	acs.Email = strings.ToLower(signupdt.Email)
	acs.ContactNo = signupdt.Contact
	acs.VerifyStatus = "not_verified"
	acs.CreationDate = time.Now().Unix()

	//validation check on password

	if !methods.CheckPassword(signupdt.Password) {

		c.JSON(400, gin.H{"error": true, "message": "Minimum eight characters, at least one uppercase letter, at least one lowercase letter, at least one number and at least one special character."})
		return
	}

	// save hash password insted of normal password

	acs.Password = methods.HashForNewPassword(signupdt.Password)

	// passing account details to save in db and send mail for verification

	msg, ok := signup.Signup(acs, signupdt.Password)

	c.JSON(200, gin.H{"error": !(ok), "message": msg})
}

//==============================================================================

// Email defining structure for binding send code again data
type Email struct {
	Email string `json:"email" binding:"required"`
}

// SendCodeAgain is api handler for sending verification code again
func SendCodeAgain(c *gin.Context) {

	var email Email
	if err := c.BindJSON(&email); err != nil {

		// if there is some error passing bad status code
		c.JSON(400, gin.H{"error": true, "message": "Email is required."})
		return
	}

	if !methods.ValidateEmail(email.Email) {

		// if there is some error passing bad status code
		c.JSON(http.StatusBadRequest, gin.H{"error": true, "message": "Please enter valid email id."})
		return
	}

	// passing passed email to sendcodeagain function and in response boolean or message

	msg, ok := signup.SendCodeAgain(strings.ToLower(email.Email))

	// checking boolean is true or false
	if !ok {
		// if false sending unable to send code again
		c.JSON(400, gin.H{"error": !(ok), "message": msg})
		return
	}

	c.JSON(200, gin.H{"error": !(ok), "message": msg})
}

//==============================================================================
