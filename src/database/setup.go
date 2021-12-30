package database

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"git.xenonstack.com/akirastack/continuous-security-auth/config"
)

func CreateDatabaseTables() {
	// connecting db using connection string
	db := config.DB

	if !(db.Migrator().HasTable(Accounts{})) {
		db.Migrator().CreateTable(Accounts{})

		//creating admin account
		adminAcc := InitAdminAccount()
		db.Create(&adminAcc)

	}

	if !(db.Migrator().HasTable(Activities{})) {
		db.Migrator().CreateTable(Activities{})
	}
	if !(db.Migrator().HasTable(Tokens{})) {
		db.Migrator().CreateTable(Tokens{})
	}
	if !(db.Migrator().HasTable(ActiveSessions{})) {
		db.Migrator().CreateTable(ActiveSessions{})
	}
	if !(db.Migrator().HasTable(Integrations{})) {
		db.Migrator().CreateTable(Integrations{})
	}
	// Database migration
	db.AutoMigrate(
		&Accounts{},
		&Activities{},
		&Tokens{},
		&ActiveSessions{},
		&Integrations{},
	)

	db.Exec(`ALTER TABLE active_sessions ADD FOREIGN KEY (userid) REFERENCES accounts(userid) ON DELETE CASCADE ON UPDATE CASCADE;`)
	db.Exec(`ALTER TABLE tokens ADD FOREIGN KEY (userid) REFERENCES accounts(userid) ON DELETE CASCADE ON UPDATE CASCADE`)
	db.Exec(`ALTER TABLE integrations ADD FOREIGN KEY (userid) REFERENCES accounts(userid) ON DELETE CASCADE ON UPDATE CASCADE`)

}

func CreateDatabase() {

	db, err := gorm.Open(postgres.Open(fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.Conf.Database.Host,
		config.Conf.Database.Port,
		config.Conf.Database.User,
		config.Conf.Database.Pass,
		"postgres", config.Conf.Database.Ssl)), &gorm.Config{})
	if err != nil {
		log.Println(err)
		return
	}

	// executing create database query.
	err = db.Exec(fmt.Sprintf("create database %s;", config.Conf.Database.Name)).Error
	log.Println(err)

}

func DeleteTables() {
	db := config.DB

	db.Migrator().DropTable(&ActiveSessions{})
	db.Migrator().DropTable(&Tokens{})

	db.Migrator().DropTable(&Activities{})
	db.Migrator().DropTable(&Accounts{})

}
