package health

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/go-redis/redis"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
)

// ServiceHealth is a method to check service each components health
func ServiceHealth() error {

	err := Healthz()
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func Healthz() error {

	db := config.DB

	//run sample query
	type Count struct {
		Count int64
	}
	var count Count
	db.Raw("select 1+1 as count").Scan(&count)
	log.Println("count...", count)
	if count.Count != 2 {
		return errors.New("db is not working")
	}

	// checking health of redis database
	// convert redis db string to int
	redisDB, err := strconv.Atoi(config.Conf.Redis.Database)
	if err != nil {
		log.Println(err)
		return errors.New("Please pass valid redis database")
	}
	//create new redis client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Conf.Redis.Host, config.Conf.Redis.Port),
		Password: config.Conf.Redis.Pass,
		DB:       redisDB,
	})
	// check connection with server
	pong, err := client.Ping().Result()
	if err != nil {
		log.Println(err)
		return errors.New("connection not maintain with redis database")
	}
	log.Println(pong)

	return nil

}
