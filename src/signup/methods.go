package signup

import (
	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/mail"
)

// initNewAccount is a method for intializing account
func initNewAccount(account *database.Accounts) {

	// if verify status is not_verified then account_status = new
	if account.VerifyStatus == "not_verified" {
		account.AccountStatus = "new"
	} else {
		account.AccountStatus = "active"
	}
	//default role will be user
	if account.RoleID == "" {
		account.RoleID = "user"
	}
}

//==============================================================================

// SendCodeAgain is a method for sending code again to email for verification
func SendCodeAgain(email string) (string, bool) {

	db := config.DB

	//Checking for email whether exists or not
	var account []database.Accounts
	db.Where("email=?", email).Find(&account)

	// if there is account and account status is new
	if len(account) != 0 {
		if account[0].VerifyStatus != "verified" {

			// send mail again
			go mail.SendVerifyMail(account[0])
			return "Verification code sent.", true
		}

		return "Your account is already verified", false
	}

	return "Email doesn't exists.", false
}
