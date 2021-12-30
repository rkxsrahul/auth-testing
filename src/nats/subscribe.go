package nats

import (
	"log"
	"os"
	"sync"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"github.com/nats-io/nats.go"
)

//printMsg : To print when a msg is recieved
func printMsg(m *nats.Msg, i int) {
	log.Printf("[#%d] Received on [%s] Pid[%d]: '%s'", i, m.Subject, os.Getpid(), string(m.Data))
}

//Subscribe : This function is used to initiate subscriber
func Subscribe() {
	var wg sync.WaitGroup
	nc := config.NC
	i := 0
	subject := "access-token"
	wg.Add(1)

	// Subscribe
	if _, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		i++
		printMsg(msg, i)
		payload := GetAccessToken(msg.Data)
		err := msg.Respond(payload)
		if err != nil {
			log.Println(err)
		}
	}); err != nil {
		log.Fatal(err)
	}

	// Wait for a message to come in
	wg.Wait()
}
