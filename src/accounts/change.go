package accounts

import (
	"errors"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
)

// ChangePassword is method for updating password
func ChangePassword(userid, oldpassword, password string) (int, bool, string) {
	// start span from parent span context

	//validation check on password

	if !methods.CheckPassword(password) {
		return 400, false, "Minimum eight characters, at least one uppercase letter, at least one lowercase letter, at least one number and at least one special character."
	}

	db := config.DB
	//check the exist password

	acc := database.Accounts{}
	db.Where("userid=?", userid).Find(&acc)

	if !methods.CheckHashForPassword(acc.Password, oldpassword) {
		return 400, false, "please pass valid current password"
	}

	if oldpassword == password {
		return 400, false, "Current and New password are same."
	}

	// creating hash for new password

	newPassHash := methods.HashForNewPassword(password)

	//updating password in db is there is user with that userid passed in parameter

	dbResult := db.Exec("update accounts set password= '" + newPassHash + "' where userid= '" + userid + "';")
	acc = GetAccountForUserid(userid)
	if dbResult.Error == nil && dbResult.RowsAffected != 0 {

		return 200, true, "Password updated successfully."
	}

	return 400, false, "Unable to change password."
}

// ======================================================================================= //
// UpdateProfile is a method to update name and contact of user
func UpdateProfile(email, name, contact string) error {
	// start span from parent span context

	// connecting to db

	// db, err := gorm.Open("postgres", config.DBConfig())
	// if err != nil {
	// 	log.Println(err)
	// 	return errors.New("Unable to connect to database")
	// }
	// // close db instance whenever whole work completed
	// defer db.Close()
	db := config.DB
	//update name of user

	var row int64
	if name != "" {
		row = db.Model(&database.Accounts{}).Where("email=?", email).Update("name", name).RowsAffected
	}
	// update contact number of user
	if contact != "" {
		row = db.Model(&database.Accounts{}).Where("email=?", email).Update("contact_no", contact).RowsAffected
	}

	if row == 0 {
		return errors.New("no account found")
	}

	return nil
}
