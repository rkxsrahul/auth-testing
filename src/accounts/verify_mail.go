package accounts

import (
	"log"
	"strconv"
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
)

// VerifyMail is method used to verify account
func VerifyMail(email, code string) (database.Accounts, bool) {

	db := config.DB
	// checking email exists or not

	var acc []database.Accounts
	db.Where("email=?", email).Find(&acc)

	if len(acc) == 0 {

		log.Println(acc[0].Email)

		return database.Accounts{}, false
	}

	//Checking token in database on basis of token and userid
	var tok []database.Tokens
	db.Where("userid= ? AND token= ? AND token_task=?", acc[0].Userid, code, "email_verification").Find(&tok)

	//when token not found
	if len(tok) == 0 {
		log.Println(tok)
		return database.Accounts{}, false
	}

	//check token is expired or not
	if (time.Now().Unix() - tok[0].Timestamp) > config.Conf.Service.VerifyLinkTimeout {

		return database.Accounts{}, false
	}

	//update account db and set verify satus to verified
	db.Model(&database.Accounts{}).Where("userid=?", tok[0].Userid).Update("verify_status", "verified")
	//if account status is 'new' then only change it to 'active'
	if acc[0].AccountStatus == "new" {
		db.Model(&database.Accounts{}).Where("userid=?", tok[0].Userid).Update("account_status", "active")
	}

	//deletion of expired tokens.
	db.Where("token_task=? AND timestamp<?", "email_verification", strconv.FormatInt((time.Now().Unix()-config.Conf.Service.VerifyLinkTimeout), 10)).Delete(&database.Tokens{})
	db.Where("token=?", code).Delete(&database.Tokens{})

	return acc[0], true
}
