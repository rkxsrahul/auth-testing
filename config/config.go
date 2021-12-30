package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

// Config is a structure for configuration
type Config struct {
	Database   Database
	Service    Service
	Address    Address
	Mail       Mail
	Admin      Admin
	Redis      Redis
	JWT        JWT
	Google     Google
	Github     Github
	NatsServer NatsServer
}

//NatsServer : for nats connection parameters
type NatsServer struct {
	URL      string
	Token    string
	Username string
	Password string
	Subject  string
	Queue    string
}

type Github struct {
	ClientID  string
	ClientKey string
	Scopes    string
	Redirect  string
	Login     string
}

// Google oAUth configuration structure
type Google struct {
	ClientID  string
	ClientKey string
	Scopes    string
	Redirect  string
	Login     string
}

// Mail is a structure for mail service configuration
type Mail struct {
	Host string
	Port string
	From string
	User string
	Pass string
}

// Admin is a structure for admin account credentials
type Admin struct {
	Email string
	Pass  string
}

// JWT is structure for jwt token specific configuration
type JWT struct {
	PrivateKey    string
	JWTExpireTime time.Duration
}

// Address is a structure that contains different-2 service addresses
type Address struct {
	Deployment      string
	FrontEndAddress string
	HostAddress     string
}

// Database is a structure for cockroach database configuration
type Database struct {
	Name  string
	Host  string
	Port  string
	User  string
	Pass  string
	Ssl   string
	Ideal string
}

// Service is a structure for service specific related configuration
type Service struct {
	Port              string
	Environment       string
	Build             string
	Mails             string
	SupportEmails     string
	ISAWS             string
	VerifyLinkTimeout int64
	InviteLinkTimeout int64
	IsLogoutOthers    string
	BaseUrl           string
}

// Redis is a structure for redis database configuration
type Redis struct {
	Database string
	Host     string
	Port     string
	Pass     string
}

// falseStr is a constant to remove duplicacy code
const (
	falseStr  string = "false"
	GroupID   string = "1001"
	GroupName string = "neuronlabs-prod"
)

var (
	// Conf is a global variable for configuration
	Conf Config
	// TomlFile is a global variable for toml file path
	TomlFile string
	// Database client
	DB *gorm.DB
	// OTP mail disabled
	OTP string = "false"

	// MailService enabled
	MailService string = "false"
	//NC for nats connection
	NC *nats.Conn
)

// ConfigurationWithEnv is a method to initialize configuration with environment variables
func ConfigurationWithEnv() {

	// redis database configuration
	Conf.Redis.Database = os.Getenv("AUTH_REDIS_DB")
	Conf.Redis.Host = os.Getenv("AUTH_REDIS_HOST")
	Conf.Redis.Port = os.Getenv("AUTH_REDIS_PORT")
	Conf.Redis.Pass = os.Getenv("AUTH_REDIS_PASS")

	// cockroach database configuration
	Conf.Database.Host = os.Getenv("AUTH_DB_HOST")
	Conf.Database.Port = os.Getenv("AUTH_DB_PORT")
	Conf.Database.User = os.Getenv("AUTH_DB_USER")
	Conf.Database.Port = os.Getenv("AUTH_DB_PASS")
	Conf.Database.Name = os.Getenv("AUTH_DB_NAME")
	Conf.Database.Ideal = os.Getenv("AUTH_DB_IDEAL_CONNECTIONS")
	Conf.Database.Ssl = "disable"

	// mail service configuration
	Conf.Mail.Host = os.Getenv("AUTH_MAIL_SMTP_HOST")
	Conf.Mail.Port = os.Getenv("AUTH_MAIL_SMTP_PORT")
	Conf.Mail.From = os.Getenv("AUTH_MAIL_FROM")
	Conf.Mail.User = os.Getenv("AUTH_MAIL_USERID")
	Conf.Mail.Pass = os.Getenv("AUTH_MAIL_PASS")

	// admin account credentials configuration
	Conf.Admin.Email = os.Getenv("AUTH_ADMIN_EMAIL")
	Conf.Admin.Pass = os.Getenv("AUTH_ADMIN_PASS")

	//Google Api
	Conf.Google.ClientID = os.Getenv("GOOGLE_CLIENTID")
	Conf.Google.ClientKey = os.Getenv("GOOGLE_CLIENTKEY")
	Conf.Google.Redirect = os.Getenv("GOOGLE_REDIRECT")
	Conf.Google.Scopes = os.Getenv("GOOGLE_SCOPES")

	//Github Api
	Conf.Github.ClientID = os.Getenv("GITHUB_CLIENTID")
	Conf.Github.ClientKey = os.Getenv("GITHUB_CLIENTKEY")
	Conf.Github.Redirect = os.Getenv("GITHUB_REDIRECT")
	Conf.Github.Scopes = os.Getenv("GITHUB_SCOPES")

	Conf.Address.FrontEndAddress = os.Getenv("HOST_ADDR")
	if Conf.Address.FrontEndAddress == "" {
		Conf.Address.FrontEndAddress = "https://continuous-security.secops.neuralcompany.team/"
	}
	// if service port is not defined set default port
	if os.Getenv("AKIRASTACK_AUTH_PORT") != "" {
		Conf.Service.Port = os.Getenv("AKIRASTACK_AUTH_PORT")

	} else {
		Conf.Service.Port = "8000"
	}

	Conf.Service.Environment = os.Getenv("ENVIRONMENT")
	Conf.Service.Build = os.Getenv("BUILD_IMAGE")
	Conf.Service.Mails = os.Getenv("NOTIFICATION_EMAILS")
	Conf.Service.SupportEmails = os.Getenv("SUPPORT_EMAIL_ADDRESS")
	if Conf.Service.SupportEmails == "" {
		Conf.Service.SupportEmails = Conf.Service.Mails
	}
	if Conf.Service.ISAWS != "true" {
		Conf.Service.ISAWS = "false"
	}
	//service specific configuration
	//default value of is logout other is true
	Conf.Service.IsLogoutOthers = "true"
	if os.Getenv("IS_LOGOUT_OTHER") == falseStr {
		Conf.Service.IsLogoutOthers = "true"
	}

	//JWT Token Timeout in minutes
	Conf.JWT.JWTExpireTime = time.Minute * 30
	//Link Expiration time in seconds
	Conf.Service.VerifyLinkTimeout = 1800
	Conf.Service.InviteLinkTimeout = 86400

}

// ConfigurationWithToml is a method to initialize configuration with toml file
func ConfigurationWithToml(filePath string) error {
	// set varible as file path if configuration is done using toml
	TomlFile = filePath
	log.Println(filePath)
	// parse toml file and save data config structure
	_, err := toml.DecodeFile(filePath, &Conf)
	if err != nil {
		log.Println(err)
		return err
	}

	if Conf.Service.Port == "" {
		Conf.Service.Port = "8000"
	}
	Conf.Database.Ssl = "disable"
	Conf.Service.Build = os.Getenv("BUILD_IMAGE")

	if Conf.Address.FrontEndAddress == "" {
		Conf.Address.FrontEndAddress = "https://continuous-security.secops.neuralcompany.team/"
	}

	if Conf.Service.SupportEmails == "" {
		Conf.Service.SupportEmails = Conf.Service.Mails
	}
	if Conf.Service.ISAWS != "true" {
		Conf.Service.ISAWS = "false"
	}

	//JWT Token Timeout in minutes
	Conf.JWT.JWTExpireTime = time.Minute * 30
	// setup configuration for jaeger opentracing
	// check value of is logout others
	if Conf.Service.IsLogoutOthers != falseStr {
		Conf.Service.IsLogoutOthers = "true"
	}
	//Link Expiration time in seconds
	Conf.Service.VerifyLinkTimeout = 1800
	Conf.Service.InviteLinkTimeout = 86400
	return nil
}

// SetConfig is a method to re-intialise configuration at runtime
func SetConfig() {
	if TomlFile == "" {
		ConfigurationWithEnv()
	} else {
		ConfigurationWithToml(TomlFile)
	}
}

// DBConfig is a method that return cockroach database connection string
func DBConfig() string {
	//again reset the config if any changes in toml file or environment variables
	SetConfig()
	// creating cockroachdb connection string
	str := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		Conf.Database.User,
		Conf.Database.Pass,
		Conf.Database.Host,
		Conf.Database.Port,
		Conf.Database.Name,
		Conf.Database.Ssl)

	return str
}
