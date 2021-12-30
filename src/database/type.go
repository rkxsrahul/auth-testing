package database

import (
	"time"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
	"git.xenonstack.com/akirastack/continuous-security-auth/src/methods"
)

// Accounts is a strucutre to stores user information
type Accounts struct {
	Userid        int    `json:"userid" gorm:"primary_key"`
	Password      string `json:"-"`
	Email         string `json:"email" gorm:"not null;unique_index;"`
	Name          string `json:"name"`
	ContactNo     string `json:"contact_no"`
	VerifyStatus  string `json:"verify_status"`
	RoleID        string `json:"sys_role"`
	AccountStatus string `json:"account_status"`
	CreationDate  int64
	CreatedAt     time.Time `json:"created_at"`
}

// Integrations save 3rd party integration tokens
type Integrations struct {
	ID           int       `json:"-" gorm:"primary_key"`
	Userid       int       `json:"-" gorm:"not null;unique_index:indx_results;"`
	Token        string    `json:"token" gorm:"not null;unique_index:indx_results;"`
	RefreshToken string    `json:"refresh-token" gorm:"unique_index:indx_results;`
	Method       string    `json:"type" gorm:"not null;unique_index:indx_results;"`
	Username     string    `json:"username" gorm:"not null;unique_index:indx_results;"`
	CreatedAt    time.Time `json:"-"`
	UpdatedAt    time.Time `json:"-"`
}

// Activities is a structure to record user activties
type Activities struct {
	ID           int       `json:"id" gorm:"primary_key"`
	Email        string    `json:"email"`
	ActivityName string    `json:"activity_name"`
	ClientIP     string    `json:"client_ip"`
	ClientAgent  string    `json:"client_agent"`
	Timestamp    int64     `json:"timestamp"`
	CreatedAt    time.Time `json:"created_at"`
}

// Tokens is a structure to stores token for verifcation, invite link, forgot password
type Tokens struct {
	ID        int `json:"id" gorm:"primary_key"`
	Userid    int
	Token     string
	TokenTask string
	Timestamp int64
	CreatedAt time.Time `json:"created_at"`
}

// ActiveSessions is a structure to stores active sessions
type ActiveSessions struct {
	ID          int `json:"id" gorm:"primary_key"`
	SessionID   string
	Userid      int
	ClientAgent string
	Start       int64
	End         int64
}

// InitAdminAccount is a function used to create admin account
func InitAdminAccount() Accounts {

	// fetching info from env variables
	adminEmail := config.Conf.Admin.Email
	if adminEmail == "" {
		adminEmail = "admin@xenonstack.com"
	}
	adminPass := config.Conf.Admin.Pass
	if adminPass == "" {
		adminPass = "admin"
	}
	// return struct with details of admin
	return Accounts{Userid: 0,
		Password:      methods.HashForNewPassword(adminPass),
		Email:         adminEmail,
		Name:          adminEmail,
		RoleID:        "admin",
		AccountStatus: "active",
		VerifyStatus:  "verified",
		CreationDate:  time.Now().Unix()}
}
