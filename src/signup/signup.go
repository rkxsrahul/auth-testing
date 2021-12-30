package signup

import (
	"fmt"
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/mail"
)

// new is a constant to remove duplicacy code
const new string = "new"

// Signup is a method for creating account if account is already not preset and send mail for verification
func Signup(newAccount database.Accounts, passwrd string) (string, bool) {

	// connecting to db
	db := config.DB

	//Checking for email whether already exists or not
	var oldAccount []database.Accounts
	db.Where("email ILIKE ?", newAccount.Email).Find(&oldAccount)

	// if no account is there with that email
	if len(oldAccount) == 0 {
		// initializing new account

		initNewAccount(&newAccount)

		// creating new account

		db.Create(&newAccount)
		// sending mail when account status is new
		if newAccount.AccountStatus == new {
			//send verification mail
			go mail.SendVerifyMail(newAccount)
			return "We have sent a confirmation link to your email, please check your email.", true
		}

		return "Registered successfully.", true
	}

	// when there is account with that email but status is new means not verified
	if oldAccount[0].AccountStatus == "new" {

		// delete previous account details
		db.Exec("delete from accounts where userid='" + fmt.Sprint(oldAccount[0].Userid) + "';")
		oldAccount[0].Name = newAccount.Name
		oldAccount[0].Password = newAccount.Password
		// creating account with new details

		db.Create(&oldAccount[0])
		//send verification mail

		go mail.SendVerifyMail(oldAccount[0])
		return "We have sent a confirmation link to your email, please check your email.", true
	}

	return "Email Already Exists.", false
}

//==============================================================================

// WithEmail is a method used to create account with email only
func WithEmail(email string) (database.Accounts, error) {
	// connecting to db
	// db, err := gorm.Open("postgres", config.DBConfig())
	// if err != nil {
	// 	log.Println(err)
	// 	return database.Accounts{}, errors.New("Unable to connect to database")
	// }
	// // close db instance whenever whole work completed
	// defer db.Close()

	//check account already exist
	db := config.DB
	acc := []database.Accounts{}
	db.Where("email=?", email).Find(&acc)
	if len(acc) != 0 {
		return acc[0], nil
	}

	// new account structure
	newAccount := database.Accounts{
		Email:         email,
		VerifyStatus:  "not_verified",
		AccountStatus: "new",
		CreationDate:  time.Now().Unix(),
	}

	// initialize new account
	initNewAccount(&newAccount)
	// create account in database
	db.Create(&newAccount)
	return newAccount, nil
}
