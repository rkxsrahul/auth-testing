package mail

import (
	"log"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/verifyToken"
)

// SendVerifyMail is a method for sending verification code in mail
func SendVerifyMail(account database.Accounts) {
	// map saving name of user and verification code for email verification
	mapd := map[string]interface{}{
		"Name":             account.Name,
		"VerificationCode": verifyToken.CheckSentToken(account.Userid, "email_verification"),
	}

	// readtoml file to fetch template path, subject and images path to be passed in mail
	tmplPath, subject, images := ReadToml("verification")

	// parse email template
	tmpl := EmailTemplate(tmplPath, mapd)
	//finally send mail
	go SendMail(account.Email, subject, tmpl, images)
}

//SendForgotPassMail is a method for sending reset password link in mail
func SendForgotPassMail(account database.Accounts) {
	// map saving name of user and reset password link for forgot password
	mapd := map[string]interface{}{
		"VerificationCode": config.Conf.Address.FrontEndAddress + "/auth/resetPassword?token=" + verifyToken.CheckSentToken(account.Userid, "forgot_pass"),
	}
	log.Println(mapd)

	// readtoml file to fetch template path, subject and images path to be passed in mail
	tmplPath, subject, images := ReadToml("forgotPassword")

	// parse email template
	tmpl := EmailTemplate(tmplPath, mapd)
	//finally send mail
	go SendMail(account.Email, subject, tmpl, images)
}
