package jwtToken

import (
	"fmt"
	"log"
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/ginjwt"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/redisdb"
)

// JwtToken is a method for creating claims map to be added in a token
// and also save sessions in cockroach database and redis database
func JwtToken(acs database.Accounts) map[string]interface{} {
	// start span from parent span contex

	// intialise claims map

	claims := make(map[string]interface{})
	// populate claims map
	claims["id"] = acs.Userid
	claims["name"] = acs.Name
	claims["email"] = acs.Email
	claims["sys_role"] = acs.RoleID

	// generate jwt token, expiration time and extra info like (expire jwt time, start and end time)

	mapd, _ := ginjwt.GinJwtToken(claims)

	// check token is empty or not
	if mapd["token"].(string) == "" {

		return mapd
	}

	// // remove all other sessions from session storage and save this session
	// SaveSessions(acs.Userid, mapd["token"].(string), info)

	return mapd
}

// JwtRefreshToken is a method for save old claims in a token
// and also save sessions in cockroach database and redis database
func JwtRefreshToken(claims map[string]interface{}) map[string]interface{} {
	// start span from parent span contex

	// intialise claims map

	// generate jwt token, expiration time and extra info like (expire jwt time, start and end time)

	mapd, _ := ginjwt.GinJwtToken(claims)

	// check token is empty or not
	if mapd["token"].(string) == "" {

		return mapd
	}

	// remove all other sessions from session storage and save this session

	return mapd
}

// SaveSessions is a method for saving session details in redis and cockroachdb
func SaveSessions(userid int, newSessToken string, info map[string]interface{}) {
	// save token in redis

	db := config.DB
	// deleting other active sessions of that user
	if config.Conf.Service.IsLogoutOthers == "true" {
		// fetch active session from dbs
		var actses []database.ActiveSessions
		db.Where("userid=?", userid).Find(&actses)
		// delete active session from redis
		for i := 0; i < len(actses); i++ {
			if actses[i].End >= time.Now().Unix() {
				err := redisdb.DeleteToken(actses[i].SessionID)
				if err != nil {
					log.Println(err)
				}
				// log.Println(val)
			}
		}
		// delete all session from db
		db.Exec("delete from active_sessions where userid= '" + fmt.Sprint(userid) + "';")
	}

	// creating one active session
	db.Create(&database.ActiveSessions{
		Userid:    userid,
		SessionID: newSessToken,
		Start:     info["start"].(int64),
		End:       info["end"].(int64)})
}

// DeleteTokenFromDb is a method to delete saved jwt token from db
func DeleteTokenFromDb(token string) {

	db := config.DB
	db.Exec("delete from active_sessions where session_id= '" + token + "';")
}
