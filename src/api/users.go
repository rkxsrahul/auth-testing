package api

import (
	"log"

	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
	jwt "github.com/appleboy/gin-jwt"

	"github.com/gin-gonic/gin"
)

// GetUserProfile is a api handler to fetch users details
// func GetUserProfile(c *gin.Context) {
// 	acc, err := accounts.GetAccountForEmail(strings.ToLower(c.Param("email")))
// 	if err != nil {
// 		c.JSON(500, gin.H{
// 			"error":   true,
// 			"message": err.Error(),
// 		})
// 		return
// 	}
// 	c.JSON(200, gin.H{
// 		"error":   false,
// 		"account": acc,
// 	})
// }

// ViewProfile is a api handler for viewing user profile
func ViewProfile(c *gin.Context) {

	// extracting jwt claims

	claims := jwt.ExtractClaims(c)

	// fetch profile on basis of email

	acc, err := accounts.GetAccountForEmail(claims["email"].(string))
	if err != nil {

		c.JSON(500, gin.H{
			"error":   true,
			"message": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"error":   false,
		"account": acc,
	})
}

// UpdateData is a structure for binding update profile data
type UpdateData struct {
	Name    string `json:"name"`
	Contact string `json:"contact"`
}

// UpdateProfile is a api handler for updating user profile
func UpdateProfile(c *gin.Context) { // fetch opentracing span from context

	// extracting jwt claims

	claims := jwt.ExtractClaims(c)

	email, ok := claims["email"]

	if !ok {
		c.JSON(500, gin.H{
			"error":   true,
			"message": "Please login again",
		})
		return
	}

	// fetching data from request body

	var data UpdateData
	if err := c.BindJSON(&data); err != nil {
		log.Println(err)
		c.JSON(400, gin.H{
			"error":   true,
			"message": "Please pass valid name and contact number",
		})
		return
	}

	//update name and contact of user

	err := accounts.UpdateProfile(email.(string), data.Name, data.Contact)
	if err != nil {

		log.Println(err)
		c.JSON(500, gin.H{
			"error":   true,
			"message": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"error":   false,
		"message": "Profile Updated Successfully",
	})
}
