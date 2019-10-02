package models

import "github.com/dgrijalva/jwt-go"

type UserClaim struct {
	UserId uint `json:"user_id"`
	jwt.StandardClaims
}
