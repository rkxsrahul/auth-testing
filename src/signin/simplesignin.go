package signin

import (
	"strconv"
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/jwtToken"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
)

func SimpleSignin(email, password string) (int, map[string]interface{}) {
	mapd := make(map[string]interface{})

	//connection to db
	db := config.DB

	//Checking whether registered or not
	var account []database.Accounts
	db.Where("email=?", email).Find(&account)

	// when no account found
	if len(account) == 0 {
		mapd["error"] = true
		mapd["message"] = "Account doesn’t exist"
		return 401, mapd
	}

	// checking previous failed logins
	msg, isAccLocked, count := checkPreviousFailedLogins(account[0])
	if isAccLocked {
		// when account is locked
		mapd["error"] = true
		mapd["message"] = msg
		return 401, mapd
	}

	// checking password with saved password
	if methods.CheckHashForPassword(account[0].Password, password) {
		// when password matched
		// checking account status
		switch account[0].AccountStatus {
		case "active":
			// when user is active all well//generate jwt token
			mapd = jwtToken.JwtToken(account[0])
			mapd["name"] = account[0].Name
			mapd["role_id"] = account[0].RoleID
			mapd["email"] = account[0].Email
			return 200, mapd
		case "blocked":
			// when user is blocked
			mapd["error"] = true
			mapd["message"] = "Your account has been blocked."
			return 401, mapd
		case "new":
			// when user is new not verified
			mapd["error"] = true
			mapd["message"] = "Please verify your email."
			return 401, mapd
		}
	}
	// when password not matched
	mapd["error"] = true
	mapd["message"] = "Invalid email or password. You have " + strconv.Itoa(count) + " login attempts left"
	return 401, mapd
}

//==============================================================================

// checkPreviousFailedLogins is a method for checking previous failed login of a user
func checkPreviousFailedLogins(account database.Accounts) (string, bool, int) {
	// declaring variables
	var lockFor int64 = 3600
	var failedloginCount int
	var msg string
	var isLocked bool

	// connecting to db
	// db, err := gorm.Open("postgres", config.DBConfig())
	// if err != nil {
	// 	log.Println(err)
	// 	return "Unable to connect to database.", true, 0
	// }
	// // close db instance whenever whole work completed
	// defer db.Close()
	db := config.DB

	var LastFailedAttempt int64
	// extracting activities on bsis of userid
	var activities []database.Activities
	db.Raw("select * from activities where email= '" + account.Email + "' order by timestamp desc limit 5;").Scan(&activities)
	for i := 0; i < len(activities); i++ {
		// if activity name is failed login and checking time interval is less then lockfor
		if activities[i].ActivityName == "failedlogin" && (time.Now().Unix()-activities[i].Timestamp) < lockFor {
			if i == 0 {
				// setting last failed attemp
				LastFailedAttempt = activities[i].Timestamp
			}
			// incrementing failed login count
			failedloginCount++
		} else {
			break
		}
	}

	// is count is more then equal to 5
	if failedloginCount >= 5 {
		msg = "Your account has been locked due to five invalid attempts. Either reset your password by clicking Forgot Password or try after " + time.Duration(1e9*(lockFor-time.Now().Unix()+LastFailedAttempt)).String() + "."
		isLocked = true
		return msg, isLocked, 0
	}

	return "", false, 5 - failedloginCount
}
