package routes

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/api"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/ginjwt"
)

// V1Routes is a method in which all the service endpoints are defined
func V1Routes(router *gin.Engine) {
	// health endpoint
	router.GET("/healthz", api.Healthz)

	router.StaticFile("/openapi.yaml", "/openapi.yaml")
	// developer help endpoint
	if config.Conf.Service.Environment != "production" {
		// endpoint to read logs
		router.GET("/logs", checkToken, readLogs)
		// endpoint to read variables
		router.GET("/end", checkToken, readEnv)
	}

	// intialize v1 group
	v1 := router.Group("/v1")

	//==== Google Login ====
	v1.GET("/google/login", api.GoogleLogin)
	v1.GET("/google/callback", api.GoogleCallback)
	//==== Github Login ====
	v1.GET("/github/login", api.GitHubLogin)
	v1.GET("/github/callback", api.GitHubCallback)

	// signup routes
	// account creation endpoint
	v1.POST("/signup", api.SignupEndpoint)

	// verify mail id on basis of token
	v1.POST("/verifymail-testing", api.VerifyMail)
	// verify mail id on basis of token
	v1.POST("/verifymail", api.VerifyMailEp)
	// if verify code get expired used to send code again at mail id
	v1.POST("/send_code_again", api.SendCodeAgain)

	// login
	v1.POST("/login", api.LoginEndpoint)

	// forgot password routes
	// used to get link when user forgot password and also for reset password
	v1.POST("/forgotpass", api.ForgotPassEp)

	//setting up middleware for protected apis
	authMiddleware := ginjwt.MwInitializer()

	//Protected resources
	v1.Use(authMiddleware.MiddlewareFunc())
	{
		// adding custom middleware for checking token validity
		v1.Use(api.CheckTokenValidity)
		{
			// session apis
			v1.GET("/refresh_token", api.RefreshToken)
			v1.GET("/check_token", api.CheckToken)
			v1.GET("/logout", api.Logout)
			v1.GET("/checkIntegrations", api.CheckIntegrations)
			// user apis
			user := v1.Group("/")

			//middleware for user
			user.Use(api.CheckUser)
			{
				// profile related routes
				// api for changing password
				user.PUT("/changepass", api.ChangePasswordEp)
				// api for view profile
				user.GET("/profile", api.ViewProfile)
				// api for view profile
				user.PUT("/profile", api.UpdateProfile)

			}

		}
	}
}

// readLogs is a api handler for reading logs
func readLogs(c *gin.Context) {
	http.ServeFile(c.Writer, c.Request, "info.txt")
}

// readEnv is api handler for reading configuration variables data
func readEnv(c *gin.Context) {
	if config.TomlFile == "" {
		// if configuration is done using environment variables
		env := make([]string, 0)
		for _, pair := range os.Environ() {
			env = append(env, pair)
		}
		c.JSON(200, gin.H{
			"environments": env,
		})
	} else {
		// if configuration is done using toml file
		http.ServeFile(c.Writer, c.Request, config.TomlFile)
	}
}

// checkToken is a middleware to check header is set or not for secured api
func checkToken(c *gin.Context) {
	xt := c.Request.Header.Get("AKIRASTACK-TOKEN")
	if xt != "slAuth1010" {
		c.Abort()
		c.JSON(401, gin.H{"message": "You are not authorised."})
		return
	}
	c.Next()
}

func checkJWT(c *gin.Context) {
	token := c.Query("token")
	//fetching only token from whole string
	token = strings.TrimPrefix(token, "Bearer ")
	// parsing token and checking its validity
	_, err := jwtgo.Parse(token, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Conf.JWT.PrivateKey), nil
	})
	// if any err return nil claims
	if err != nil {
		c.AbortWithStatus(401)
		return
	}
	c.Next()
}
