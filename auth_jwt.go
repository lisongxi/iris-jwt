package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/kataras/iris/v12"
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
type MapClaims map[string]interface{}

// IrisJWTMiddleware provides a JWT authentication implementation for Iris.
type IrisJWTMiddleware struct {
	Realm                 string
	SigningAlgorithm      string
	Key                   []byte
	KeyFunc               func(token *jwt.Token) (interface{}, error)
	Timeout               time.Duration
	TimeoutFunc           func(data interface{}) time.Duration
	MaxRefresh            time.Duration
	Authenticator         func(ctx iris.Context) (interface{}, error)
	Authorizator          func(data interface{}, ctx iris.Context) bool
	PayloadFunc           func(data interface{}) MapClaims
	Unauthorized          func(ctx iris.Context, code int, message string)
	LoginResponse         func(ctx iris.Context, code int, message string, time time.Time)
	LogoutResponse        func(ctx iris.Context, code int)
	RefreshResponse       func(ctx iris.Context, code int, message string, time time.Time)
	IdentityHandler       func(ctx iris.Context) interface{}
	IdentityKey           string
	TokenLookup           string
	TokenHeadName         string
	TimeFunc              func() time.Time
	HTTPStatusMessageFunc func(e error, ctx iris.Context) string
	PrivKeyFile           string
	PrivKeyBytes          []byte
	PubKeyFile            string
	PrivateKeyPassphrase  string
	PubKeyBytes           []byte
	privKey               *rsa.PrivateKey
	pubKey                *rsa.PublicKey
	SendCookie            bool
	CookieMaxAge          time.Duration
	SecureCookie          bool
	CookieHTTPOnly        bool
	CookieDomain          string
	SendAuthorization     bool
	DisabledAbort         bool
	CookieName            string
	CookieSameSite        http.SameSite
	ParseOptions          []jwt.ParserOption
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("irisJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired") // in practice, this is generated from the jwt library not by us

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// IdentityKey default identity key
	IdentityKey = "identity"
)

// New for check error with IrisJWTMiddleware
func New(m *IrisJWTMiddleware) (*IrisJWTMiddleware, error) {
	if err := m.MiddlewareInit(); err != nil {
		return nil, err
	}
	return m, nil
}

func (mw *IrisJWTMiddleware) readKeys() error {
	err := mw.privateKey()
	if err != nil {
		return err
	}
	return mw.publicKey()
}

func (mw *IrisJWTMiddleware) privateKey() error {
	var keyData []byte
	if mw.PrivKeyFile == "" {
		keyData = mw.PrivKeyBytes
	} else {
		filecontent, err := os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}
	if mw.PrivateKeyPassphrase != "" {
		key, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyData, mw.PrivateKeyPassphrase)
		if err != nil {
			return ErrInvalidPrivKey
		}
		mw.privKey = key
		return nil
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

func (mw *IrisJWTMiddleware) publicKey() error {
	var keyData []byte
	if mw.PubKeyFile == "" {
		keyData = mw.PubKeyBytes
	} else {
		filecontent, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = filecontent
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *IrisJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// MiddlewareInit initialize jwt configs.
func (mw *IrisJWTMiddleware) MiddlewareInit() error {
	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeoutFunc == nil {
		mw.TimeoutFunc = func(data interface{}) time.Duration {
			return mw.Timeout
		}
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, ctx iris.Context) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(ctx iris.Context, code int, message string) {
			ctx.StatusCode(code)
			ctx.JSON(iris.Map{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.LoginResponse == nil {
		mw.LoginResponse = func(ctx iris.Context, code int, token string, expire time.Time) {
			ctx.JSON(iris.Map{
				"code":   iris.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(ctx iris.Context, code int) {
			ctx.JSON(iris.Map{
				"code": iris.StatusOK,
			})
		}
	}

	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(ctx iris.Context, code int, token string, expire time.Time) {
			ctx.JSON(iris.Map{
				"code":   iris.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.IdentityKey == "" {
		mw.IdentityKey = IdentityKey
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(ctx iris.Context) interface{} {
			claims := ExtractClaims(ctx)
			return claims[mw.IdentityKey]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, ctx iris.Context) string {
			return e.Error()
		}
	}

	if mw.Realm == "" {
		mw.Realm = "iris jwt"
	}

	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	if mw.KeyFunc != nil {
		return nil
	}

	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}

	if mw.Key == nil {
		return ErrMissingSecretKey
	}
	return nil
}

// MiddlewareFunc makes IrisJWTMiddleware implement the Middleware interface.
func (mw *IrisJWTMiddleware) MiddlewareFunc() iris.Handler {
	return func(ctx iris.Context) {
		mw.middlewareImpl(ctx)
	}
}

func (mw *IrisJWTMiddleware) middlewareImpl(ctx iris.Context) {
	claims, err := mw.GetClaimsFromJWT(ctx)
	if err != nil {
		mw.unauthorized(ctx, iris.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, ctx))
		return
	}

	switch v := claims["exp"].(type) {
	case nil:
		mw.unauthorized(ctx, iris.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingExpField, ctx))
		return
	case float64:
		if int64(v) < mw.TimeFunc().Unix() {
			mw.unauthorized(ctx, iris.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, ctx))
			return
		}
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			mw.unauthorized(ctx, iris.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, ctx))
			return
		}
		if n < mw.TimeFunc().Unix() {
			mw.unauthorized(ctx, iris.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, ctx))
			return
		}
	default:
		mw.unauthorized(ctx, iris.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, ctx))
		return
	}

	ctx.Values().Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(ctx)

	if identity != nil {
		ctx.Values().Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, ctx) {
		mw.unauthorized(ctx, iris.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, ctx))
		return
	}

	ctx.Next()
}

// GetClaimsFromJWT get claims from JWT token
func (mw *IrisJWTMiddleware) GetClaimsFromJWT(ctx iris.Context) (MapClaims, error) {
	token, err := mw.ParseToken(ctx)
	if err != nil {
		return nil, err
	}

	if mw.SendAuthorization {
		if v := ctx.Values().GetString("JWT_TOKEN"); v != "" {
			ctx.Header("Authorization", mw.TokenHeadName+" "+v)
		}
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

// LoginHandler can be used by clients to get a jwt token.
func (mw *IrisJWTMiddleware) LoginHandler(ctx iris.Context) {
	if mw.Authenticator == nil {
		mw.unauthorized(ctx, iris.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, ctx))
		return
	}

	data, err := mw.Authenticator(ctx)
	if err != nil {
		mw.unauthorized(ctx, iris.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, ctx))
		return
	}

	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		mw.unauthorized(ctx, iris.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, ctx))
		return
	}

	mw.SetCookie(ctx, tokenString)

	mw.LoginResponse(ctx, iris.StatusOK, tokenString, expire)
}

// LogoutHandler can be used by clients to remove the jwt cookie (if set)
func (mw *IrisJWTMiddleware) LogoutHandler(ctx iris.Context) {
	if mw.SendCookie {
		ctx.RemoveCookie(mw.CookieName, iris.CookieExpires(0), iris.CookiePath("/"))
	}

	mw.LogoutResponse(ctx, iris.StatusOK)
}

func (mw *IrisJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if mw.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		tokenString, err = token.SignedString(mw.Key)
	}
	return tokenString, err
}

// RefreshHandler can be used to refresh a token.
func (mw *IrisJWTMiddleware) RefreshHandler(ctx iris.Context) {
	tokenString, expire, err := mw.RefreshToken(ctx)
	if err != nil {
		mw.unauthorized(ctx, iris.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, ctx))
		return
	}

	mw.RefreshResponse(ctx, iris.StatusOK, tokenString, expire)
}

// RefreshToken refresh token and check if token is expired
func (mw *IrisJWTMiddleware) RefreshToken(ctx iris.Context) (string, time.Time, error) {
	claims, err := mw.CheckIfTokenExpire(ctx)
	if err != nil {
		return "", time.Now(), err
	}

	origIat, ok := claims["orig_iat"]
	if !ok {
		return "", time.Now(), errors.New("orig_iat not present in token")
	}

	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = origIat

	tokenString, err := mw.signedString(newToken)
	if err != nil {
		return "", time.Now(), err
	}

	mw.SetCookie(ctx, tokenString)
	return tokenString, expire, nil
}

// CheckIfTokenExpire check if token expire
func (mw *IrisJWTMiddleware) CheckIfTokenExpire(ctx iris.Context) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(ctx)
	if err != nil {
		var validationErr *jwt.ValidationError
		if errors.As(err, &validationErr) && validationErr.Errors == jwt.ValidationErrorExpired {
		} else {
			return nil, err
		}
	}

	claims := token.Claims.(jwt.MapClaims)

	origIatValue := claims["orig_iat"]
	var origIat int64

	switch v := origIatValue.(type) {
	case float64:
		origIat = int64(v)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return nil, err
		}
		origIat = n
	default:
		return nil, errors.New("invalid orig_iat format")
	}

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// TokenGenerator method that clients can use to get a jwt token.
func (mw *IrisJWTMiddleware) TokenGenerator(data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.TimeoutFunc(claims))
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *IrisJWTMiddleware) jwtFromHeader(ctx iris.Context, key string) (string, error) {
	authHeader := ctx.GetHeader(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == mw.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *IrisJWTMiddleware) jwtFromQuery(ctx iris.Context, key string) (string, error) {
	token := ctx.URLParam(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (mw *IrisJWTMiddleware) jwtFromCookie(ctx iris.Context, key string) (string, error) {
	cookie := ctx.GetCookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *IrisJWTMiddleware) jwtFromParam(ctx iris.Context, key string) (string, error) {
	token := ctx.Params().Get(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (mw *IrisJWTMiddleware) jwtFromForm(ctx iris.Context, key string) (string, error) {
	token := ctx.FormValue(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// ParseToken parse jwt token from iris context
func (mw *IrisJWTMiddleware) ParseToken(ctx iris.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(ctx, v)
		case "query":
			token, err = mw.jwtFromQuery(ctx, v)
		case "cookie":
			token, err = mw.jwtFromCookie(ctx, v)
		case "param":
			token, err = mw.jwtFromParam(ctx, v)
		case "form":
			token, err = mw.jwtFromForm(ctx, v)
		}
	}

	if err != nil {
		return nil, err
	}

	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		ctx.Values().Set("JWT_TOKEN", token)

		return mw.Key, nil
	}, mw.ParseOptions...)
}

// ParseTokenString parse jwt token string
func (mw *IrisJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		return mw.Key, nil
	}, mw.ParseOptions...)
}

func (mw *IrisJWTMiddleware) unauthorized(ctx iris.Context, code int, message string) {
	ctx.Header("WWW-Authenticate", "JWT realm="+mw.Realm)
	if !mw.DisabledAbort {
		ctx.StopExecution()
	}

	mw.Unauthorized(ctx, code, message)
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(ctx iris.Context) MapClaims {
	claims := ctx.Values().Get("JWT_PAYLOAD")
	if claims == nil {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

// ExtractClaimsFromToken helps to extract the JWT claims from a token
func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// SetCookie sets the JWT token as a cookie
func (mw *IrisJWTMiddleware) SetCookie(ctx iris.Context, tokenString string) {
	if mw.SendCookie {
		ctx.SetCookie(&http.Cookie{
			Name:     mw.CookieName,
			Value:    tokenString,
			MaxAge:   int(mw.CookieMaxAge.Seconds()),
			Path:     "/",
			Domain:   mw.CookieDomain,
			Secure:   mw.SecureCookie,
			HttpOnly: mw.CookieHTTPOnly,
			SameSite: mw.CookieSameSite,
		})
	}
}
