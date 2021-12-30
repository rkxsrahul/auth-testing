package accounts

import (
	"errors"
	"log"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/redisdb"
)

// GetAccountForUserid is a method used to get account details on basis of userid
func GetAccountForUserid(userid string) database.Accounts {
	// connecting to db
	db := config.DB

	// intialize variable with type accounts
	var acs []database.Accounts
	// fetching data on basis of userid
	db.Where("userid= ?", userid).Find(&acs)

	// if there is account pass the first element of array
	if len(acs) != 0 {
		return acs[0]
	}
	// if there is no account pass null values
	return database.Accounts{}
}

//==============================================================================

// GetAccountForEmail is a method used to get account details on basis of email
func GetAccountForEmail(email string) (database.Accounts, error) {
	// connecting to db
	db := config.DB

	// intialize variable with type accounts
	var acs []database.Accounts
	// fetching data on basis of email
	db.Where("email=?", email).Find(&acs)

	// if there is account pass the first element of array
	if len(acs) != 0 {
		return acs[0], nil
	}
	// if there is no account pass null values
	return database.Accounts{}, errors.New("No account found")
}

//==============================================================================

// GetAllAccounts is a method used to get all account details
func GetAllAccounts() ([]database.Accounts, error) {
	// connecting to db
	db := config.DB

	// intialize variable with type accounts
	var acs []database.Accounts
	// fetching data from db
	db.Where("role_id=? AND verify_status=?", "user", "verified").Find(&acs)

	// return all accounts
	return acs, nil
}

//==============================================================================

// DeleteAccount is a method used to delete an account
func DeleteAccount(email string) error {
	// connecting to db
	db := config.DB

	//fetch account
	acc, err := GetAccountForEmail(email)
	if err != nil {

		return err
	}
	if acc.Userid != 0 && acc.RoleID != "admin" {
		// delete all tokens
		var sessions []database.ActiveSessions
		db.Where("userid=?", acc.Userid).Find(&sessions)
		for i := 0; i < len(sessions); i++ {
			redisdb.DeleteToken(sessions[i].SessionID)

		}

		//delete from database tables
		row := db.Where("userid=?", acc.Userid).Delete(&database.Accounts{})
		log.Println("accounts...", row)
		row = db.Where("userid=?", acc.Userid).Delete(&database.Tokens{})
		log.Println("token...", row)
		row = db.Where("email=?", acc.Email).Delete(&database.Activities{})
		log.Println("activites...", row)
		row = db.Where("userid=?", acc.Userid).Delete(&database.ActiveSessions{})
		log.Println("sessiom...", row)

	} else {
		return errors.New("You cannot delete admin account")
	}

	return nil
}

//CheckIntegrations function used for the check he integration information
func CheckIntegrations(id, method string) (map[string]interface{}, int) {

	mapd := make(map[string]interface{})
	db := config.DB

	//declare the object
	info := database.Integrations{}

	//fetch the information from database
	db.Where("userid=? and method=?", id, method).Find(&info)
	if info.ID == 0 {
		mapd["error"] = true
		mapd["message"] = "Information not exists for " + method
		return mapd, 400
	}

	mapd["error"] = false
	mapd["data"] = info
	return mapd, 200
}
