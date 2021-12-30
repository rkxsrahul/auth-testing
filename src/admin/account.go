package admin

import (
	"git.xenonstack.com/akirastack/continuous-security-auth/src/accounts"
)

// DeleteAccount is a method to delete a account from database
func DeleteAccount(email string) error {

	//delete account from core auth
	err := accounts.DeleteAccount(email)

	return err
}
