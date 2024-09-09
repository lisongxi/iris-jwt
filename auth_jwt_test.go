package jwt

import (
	"github.com/kataras/iris/v12"
)

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(c *iris.Context) (interface{}, error) {
		var loginVals Login
		userID := loginVals.Username
		password := loginVals.Password

		if userID == "admin" && password == "admin" {
			return userID, nil
		}

		return userID, ErrFailedAuthentication
	}
)
