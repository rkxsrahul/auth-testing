package nats

import (
	"encoding/json"
	"log"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/database"
)

//GetAccessToken is used to get accesstoken on the basis of userid
func GetAccessToken(data []byte) []byte {
	db := config.DB
	var token database.Integrations
	err := db.Where("userid=?", string(data)).Find(&token).Error
	if err != nil {
		log.Println(err)
		return []byte(err.Error())
	}
	tokendata, err := json.Marshal(token)
	if err != nil {
		log.Println(err)
		return []byte("no integration available")
	}
	return tokendata
}
