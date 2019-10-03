package jwt

import (
	"errors"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/doge-soft/dogego_module_jwt/models"
	"github.com/go-redis/redis"
	"os"
	"time"
)

const (
	HOUR  = 3600
	DAY   = HOUR * 24
	MOUTH = DAY * 30
)

var (
	TokenExpired     error = errors.New("Token 已经过期")
	TokenNotValidYet error = errors.New("Token 没有激活")
	TokenMalformed   error = errors.New("这不是一个有效的Token")
	TokenInvalid     error = errors.New("无法处理这个Token")
)

type RedisJWT struct {
	RedisClient *redis.Client
}

func NewRedisJWT(redisClient *redis.Client) *RedisJWT {
	return &RedisJWT{
		RedisClient: redisClient,
	}
}

func (jwt *RedisJWT) GenerateToken(claim *models.UserClaim) (string, error) {
	claim.Issuer = "DogeGo"
	claim.Audience = "DogeGoAPI"
	claim.IssuedAt = time.Now().Unix()
	claim.Subject = "DogeGoJWT"
	claim.ExpiresAt = int64(MOUTH)
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claim)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		return "", err
	}

	err = jwt.RedisClient.Set(tokenString, "true", 0).Err()

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (jwt *RedisJWT) DieToken(tokenString string) error {
	err := jwt.RedisClient.Del(tokenString).Err()

	if err != nil {
		return err
	}

	return nil
}

func (jwt *RedisJWT) CheckToken(tokenString string) (*models.UserClaim, error) {
	tokenResult, err := jwt.RedisClient.Get(tokenString).Result()

	if err != nil {
		return nil, err
	}

	if tokenResult == "" {
		return nil, TokenMalformed
	}

	token, err := jwtgo.ParseWithClaims(tokenString, &models.UserClaim{}, func(token *jwtgo.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		if ve, ok := err.(*jwtgo.ValidationError); ok {
			if ve.Errors&jwtgo.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
			} else if ve.Errors&jwtgo.ValidationErrorExpired != 0 {
				// Token is expired
				return nil, TokenExpired
			} else if ve.Errors&jwtgo.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
			} else {
				return nil, TokenInvalid
			}
		}
	}

	if claims, ok := token.Claims.(*models.UserClaim); ok && token.Valid {
		return claims, nil
	}

	return nil, TokenInvalid
}
