package middlewares

import (
	jwtm "github.com/doge-soft/dogego_module_jwt/jwt"
	"github.com/gin-gonic/gin"
)

type JwtMiddleware struct {
	JwtModule *jwtm.RedisJWT
}

func NewJwtMiddleware(jwt_module *jwtm.RedisJWT) *JwtMiddleware {
	return &JwtMiddleware{
		JwtModule: jwt_module,
	}
}

func (middleware *JwtMiddleware) New() gin.HandlerFunc {
	return func(context *gin.Context) {
		// 获取头信息
		token := context.GetHeader("Authorizion")
		claim, err := middleware.JwtModule.CheckToken(token)

		if err != nil {
			context.AbortWithStatus(500)
		}

		context.Set("claims", claim)
		context.Next()
	}
}
