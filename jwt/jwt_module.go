package jwt

import (
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/doge-soft/dogego_module_jwt/models"
	"os"
	"time"
)

const (
	HOUR  = 3600
	DAY   = HOUR * 24
	MOUTH = DAY * 30
)

type RedisJWT struct {
}

func (jwt *RedisJWT) GenerateToken(claim *models.UserClaim) (string, error) {
	claim.Issuer = "DogeGo"
	claim.Audience = "DogeGoAPI"
	claim.IssuedAt = time.Now().Unix()
	claim.Subject = "DogeGoJWT"
	claim.ExpiresAt = int64(MOUTH)
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claim)

	return token.SignedString(os.Getenv("JWT_SECRET"))
}

func (jwt *RedisJWT) CheckToken() bool {

}
