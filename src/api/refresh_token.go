package api

import (
	"strings"

	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/jwtToken"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/redisdb"
)

// CheckToken is API for checking token is valid
func CheckToken(c *gin.Context) {
	c.JSON(200, gin.H{})
}

// RefreshToken is api handler to generate new jwt token and expire old token
func RefreshToken(c *gin.Context) {
	// fetch opentracing span from context

	// extracting jwt claims

	claims := jwt.ExtractClaims(c)

	// fetch account on basis of userid

	acc := accounts.GetAccountForUserid(claims["id"].(string))
	// generating new token

	mapd := jwtToken.JwtRefreshToken(claims)
	mapd["name"] = acc.Name
	mapd["email"] = acc.Email
	mapd["sys_role"] = acc.RoleID

	// if any error in genrating new token
	if mapd["token"] == "" {

		c.JSON(501, gin.H{
			"error":   true,
			"message": "Error in generating new token",
		})
		return
	}
	if config.Conf.Service.IsLogoutOthers != "true" {
		// when succesfully generated new token
		// delete old token from redis
		// fetch token from header

		token := c.Request.Header.Get("Authorization")
		// trim bearer from token
		token = strings.TrimPrefix(token, "Bearer ")
		// call delete token go function

		err := redisdb.DeleteToken(token)
		if err != nil {

			c.JSON(501, gin.H{
				"error":   err,
				"message": "Error in deleting old token",
			})
			return
		}
	}

	c.JSON(200, mapd)
}

// CheckTokenValidity is a middleware for checking token validity using redis database
func CheckTokenValidity(c *gin.Context) {

	token := c.Request.Header.Get("Authorization")
	// trim bearer from token
	token = strings.TrimPrefix(token, "Bearer ")

	// check token exist or not

	err := redisdb.CheckToken(token)
	if err != nil {
		// when token not exist

		c.Abort()
		c.JSON(401, gin.H{"error": true, "message": "Expired auth token"})
		return
	}

	c.Next()
}

// CheckAdmin is a middleware for checking user is admin or not
// func CheckAdmin(c *gin.Context) {
// 	// fetch opentracing span from context

// 	claims := jwt.ExtractClaims(c)
// 	// checking sys role
// 	if claims["sys_role"].(string) != "admin" {

// 		c.Abort()
// 		c.JSON(403, gin.H{
// 			"error":   true,
// 			"message": "You are not authorized",
// 		})
// 		return
// 	}

// 	c.Next()
// }

// CheckUser is a middleware for checking user is user or not
func CheckUser(c *gin.Context) {

	claims := jwt.ExtractClaims(c)
	// checking sys role
	if claims["sys_role"].(string) != "user" {

		c.Abort()
		c.JSON(403, gin.H{
			"error":   true,
			"message": "You are not authorized",
		})
		return
	}

	c.Next()
}

// CheckOwner is a middleware for checking workspace user is owner or not
// func CheckOwner(c *gin.Context) {
// 	// fetch opentracing span from context

// 	claims := jwt.ExtractClaims(c)

// 	// check user is owner of workpsace or user
// 	role, ok := claims["role"].(string)
// 	if !ok {

// 		c.Abort()
// 		c.JSON(403, gin.H{
// 			"error":   true,
// 			"message": "You are not authorized",
// 		})
// 		return
// 	}
// 	if role != "owner" {

// 		c.Abort()
// 		c.JSON(403, gin.H{
// 			"error":   true,
// 			"message": "You are not authorized",
// 		})
// 		return
// 	}

// 	c.Next()
// }
