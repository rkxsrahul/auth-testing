package sociallogin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/jwtToken"
)

var (
	googleConfig *oauth2.Config
)

//GoogleLogin is used to signup
func GoogleLogin(state StateInformation) string {
	googleConfig = &oauth2.Config{
		ClientID:     config.Conf.Google.ClientID,
		ClientSecret: config.Conf.Google.ClientKey,
		Scopes:       strings.Split(config.Conf.Google.Scopes, ","),
		RedirectURL:  config.Conf.Google.Redirect,
		Endpoint:     google.Endpoint,
	}
	data, _ := json.Marshal(state)
	url := googleConfig.AuthCodeURL(string(data), oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	return url
}

//GoolgeCallback is used for call back operation
func GoogleCallback(code string, state string) string {

	//Parse is used for fetching redirect url from state
	register, err := Parse(state)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	//googleconfig is used to fetch access token
	oToken, err := googleConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}
	//url to get user information
	url := "https://www.googleapis.com/oauth2/v1/userinfo"
	method := "GET"

	// request is used to fetch the data from url using access token
	body, err := Request(url, method, oToken.AccessToken)
	if err != nil {
		log.Println(err)
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}
	//store the google response
	userDetails := GoogleUserData{}

	//unmarshal the byteData
	err = json.Unmarshal(body, &userDetails)
	if err != nil {
		log.Println(err)
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	var verifystatus string
	if userDetails.VerifiedEmail {
		verifystatus = "true"
	} else {
		log.Println(userDetails.VerifiedEmail)
	}

	log.Println(userDetails)

	userData := database.Accounts{}
	userData.Password = oToken.AccessToken
	userData.Email = userDetails.Email
	userData.Name = userDetails.Name
	userData.ContactNo = ""
	userData.VerifyStatus = verifystatus
	userData.RoleID = "user"
	userData.AccountStatus = "active"
	userData.CreationDate = time.Now().Unix()

	if register.Token != "" {
		claims, err := jwtToken.ExtractClaims(register.Token)
		if err != nil {
			log.Println(err.Error())
			return register.RedirectURL + "?error=true&message=Please Login Again"
		}
		//claim the name from the token
		id, err := strconv.Atoi(fmt.Sprint(claims["id"]))
		if err != nil {
			userData.Userid = id
		}
	}

	//connect to DB
	db := config.DB

	userInfo := database.Accounts{}
	//check the email exist or not
	rows := db.Where("email=?", userData.Email).Find(&userInfo).RowsAffected

	if rows == 0 && userData.Userid == 0 {
		//create the user
		err = db.Create(&userData).Error
		if err != nil {
			log.Println(err)
			return register.RedirectURL + "?error=true&message=" + err.Error()
		}
		userdata := database.Integrations{}
		userdata.Method = "google"
		userdata.Token = oToken.AccessToken
		userdata.Username = userData.Name
		userdata.Userid = userData.Userid
		userdata.RefreshToken = oToken.RefreshToken
		userdata.CreatedAt = time.Now()
		err := db.Create(&userdata).Error
		if err != nil {
			log.Println(err)
		}
	} else {
		userData = userInfo
		err := db.Model(&database.Integrations{}).Where("userid = ?", userData.Userid).Updates(database.Integrations{Token: oToken.AccessToken, RefreshToken: oToken.RefreshToken, Username: userData.Name, Method: "google"}).Error
		if err != nil {
			log.Println(err)
		}
	}

	//generate the access token
	mapd := jwtToken.JwtToken(userData)
	mapd["name"] = userData.Name
	mapd["role_id"] = userData.RoleID
	mapd["email"] = userData.Email

	return register.RedirectURL + "?error=false&name=" + userData.Name + "&role_id=" + userData.RoleID + "&email=" + userData.Email + "&id=" + fmt.Sprint(userData.Userid) + "&token=" + fmt.Sprint(mapd["token"])
}
