package forgotpass

import (
	"errors"
	"log"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/mail"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/verifyToken"
)

//==============================================================================

// ForgotPassChallenge is a method for sending reset-password link in mail
func ForgotPass(email string) (string, bool) {

	acc, err := accounts.GetAccountForEmail(email)
	if err != nil {

		log.Println("when no account is there")
		return "Email doesn't exists.", false
	}

	if acc.VerifyStatus == "verified" && acc.AccountStatus == "active" {

		//send forgot password mail
		go mail.SendForgotPassMail(acc)

		return "We have sent a password reset link to your mail.", true

	}

	return "Email doesn't exists.", false
}

// ResetForgottenPass is method to reset password in database
// but before updating token and password is checked
func ResetForgottenPassword(token, password string) (string, string, bool) {
	// start span from parent span context

	//validation check on password

	if !methods.CheckPassword(password) {

		return "", "Minimum eight characters, at least one uppercase letter, at least one lowercase letter, at least one number and at least one special character.", false
	}

	tok, err := verifyToken.CheckToken(token)
	if err != nil {

		return "", err.Error(), false
	}

	if tok.TokenTask == "forgot_pass" {
		// update in database

		email, err := updateDatabase(tok.Userid, password)
		if err != nil {

			return "", err.Error(), false
		}
		// delete used and expired tokens
		go verifyToken.DeleteToken(token)

		//password reset done.

		return email, "Password reset successfully.", true
	}

	return "", "Invalid or expired token.", false
}

//==============================================================================

// UpdateDatabase is method to update password in database on basis of userid
func updateDatabase(userid int, password string) (string, error) {

	db := config.DB
	// check account exist
	var acs []database.Accounts
	db.Where("userid= ?", userid).Find(&acs)
	if len(acs) == 0 {
		return "", errors.New("Account not found")
	}
	// hash the simple password and then update password in database
	db.Model(&database.Accounts{}).Where("userid=?", userid).Update("password", methods.HashForNewPassword(password))

	return acs[0].Email, nil
}
