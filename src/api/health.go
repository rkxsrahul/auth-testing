package api

import (
	"log"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/health"
	"github.com/gin-gonic/gin"
)

// Healthz is an api handler to check health of service
func Healthz(c *gin.Context) {

	// call health service check function

	err := health.ServiceHealth()
	if err != nil {
		// if any error is there
		log.Println(err)
		c.JSON(500, gin.H{
			"error":   true,
			"message": err.Error(),
		})
		return
	}

	// if no error is there
	c.JSON(200, gin.H{
		"error":       false,
		"message":     "All is okay",
		"build":       config.Conf.Service.Build,
		"environment": config.Conf.Service.Environment,
	})
}
