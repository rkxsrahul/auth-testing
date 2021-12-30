package sociallogin

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/jwtToken"
)

var (
	githubConfig *oauth2.Config
)

//Githublogin is used to for signup
func GitHubLogin(state StateInformation) string {
	githubConfig = &oauth2.Config{
		ClientID:     config.Conf.Github.ClientID,
		ClientSecret: config.Conf.Github.ClientKey,
		Scopes:       strings.Split(config.Conf.Github.Scopes, ","),
		RedirectURL:  config.Conf.Github.Redirect,
		Endpoint:     github.Endpoint,
	}
	data, _ := json.Marshal(state)
	url := githubConfig.AuthCodeURL(string(data), oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	return url
}

//Github Callback is used for call back operation
func GitHubCallback(code string, state string) string {

	//Parse is used for fetching redirect url from state
	register, err := Parse(state)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	//githubconfig is used to fetch access token
	oToken, err := githubConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	url := "https://api.github.com/user/emails"
	method := "GET"
	// request is used to fetch the data from url using access token
	body, err := Request(url, method, oToken.AccessToken)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}
	//store the github response --> email and verified
	userstatusdata := []GithubUserData{}
	//unmarshal the byteData
	err = json.Unmarshal(body, &userstatusdata)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	var verifystatus string
	if userstatusdata[0].Verified {
		verifystatus = "true"
	} else {
		log.Println(userstatusdata[0].Verified)
	}

	url = "https://api.github.com/user"
	method = "GET"
	// request is used to fetch the data from url using access token
	body, err = Request(url, method, oToken.AccessToken)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	//store the github response --> login and type
	userProfile := GithubUserData2{}

	//unmarshal the byteData
	err = json.Unmarshal(body, &userProfile)
	if err != nil {
		log.Println(err)
		return register.RedirectURL + "?error=true&message=" + err.Error()
	}

	userData := database.Accounts{}
	userData.Password = oToken.AccessToken
	userData.Email = userstatusdata[0].Email
	userData.Name = userProfile.Login
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
		userdata.Method = "github"
		userdata.Token = oToken.AccessToken
		userdata.Username = userData.Name
		userdata.Userid = userData.Userid
		userdata.CreatedAt = time.Now()
		err := db.Create(&userdata).Error
		if err != nil {
			log.Println(err)
		}
	} else {
		userData = userInfo
		err := db.Model(&database.Integrations{}).Where("userid = ?", userData.Userid).Updates(database.Integrations{Token: oToken.AccessToken, RefreshToken: "", Username: userData.Name, Method: "github"}).Error
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

func Parse(state string) (StateInformation, error) {
	user := StateInformation{}
	m, _ := url.ParseQuery("state=" + state)
	some := m.Get("state")
	err := json.Unmarshal([]byte(some), &user)
	if err != nil {
		log.Println(err)
	}
	return user, nil
}

func Request(url string, method string, oToken string) ([]byte, error) {

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)

	}
	req.Header.Add("Authorization", "Bearer "+oToken)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return []byte(""), err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return []byte(""), err
	}
	return body, nil

}
