package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/fagongzi/gateway/pkg/filter"
	"github.com/valyala/fasthttp"
)

var (
	errJWTMissing = errors.New("missing jwt token")
)

type tokenGetter func(filter.Context) (string, error)

func main() {}

// JWTCfg cfg
type JWTCfg struct {
	Secret      string `json:"secret"`
	TokenLookup string `json:"tokenLookup"`
	AuthScheme  string `json:"authScheme"`
	HeadPrefix  string `json:"headPrefix"`
	secretBytes []byte
}

// JWTFilter filter
type JWTFilter struct {
	filter.BaseFilter

	cfg    JWTCfg
	getter tokenGetter
}

// NewExternalFilter returns a filter
func NewExternalFilter() (filter.Filter, error) {
	return &JWTFilter{}, nil
}

// Init init filter
func (f *JWTFilter) Init(cfg string) error {
	data, err := ioutil.ReadFile(cfg)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &f.cfg)
	if err != nil {
		return err
	}

	// Initialize
	parts := strings.Split(f.cfg.TokenLookup, ":")
	f.getter = jwtFromHeader(parts[1], f.cfg.AuthScheme)
	switch parts[0] {
	case "query":
		f.getter = jwtFromQuery(parts[1])
	case "cookie":
		f.getter = jwtFromCookie(parts[1])
	}

	f.cfg.secretBytes = []byte(f.cfg.Secret)
	return nil
}

// Name name
func (f *JWTFilter) Name() string {
	return "jwt"
}

// Pre execute before proxy
func (f *JWTFilter) Pre(c filter.Context) (statusCode int, err error) {
	if c.API().AuthFilter != f.Name() {
		return f.BaseFilter.Pre(c)
	}

	token, err := f.getter(c)
	if err != nil {
		return fasthttp.StatusForbidden, err
	}

	claims, err := f.parseJWTToken(token)
	if err != nil {
		return fasthttp.StatusForbidden, err
	}

	for key, value := range claims {
		c.OriginRequest().Request.Header.Add(fmt.Sprintf("%s%s", f.cfg.HeadPrefix, key), fmt.Sprintf("%v", value))
	}

	return f.BaseFilter.Pre(c)
}

// Post execute after proxy
func (f *JWTFilter) Post(c filter.Context) (statusCode int, err error) {
	return f.BaseFilter.Post(c)
}

func (f *JWTFilter) parseJWTToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return f.cfg.secretBytes, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("error jwt token")
}

func jwtFromHeader(header string, authScheme string) tokenGetter {
	return func(c filter.Context) (string, error) {
		auth := string(c.OriginRequest().Request.Header.Peek(header))
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", errJWTMissing
	}
}

func jwtFromQuery(param string) tokenGetter {
	return func(c filter.Context) (string, error) {
		token := string(c.OriginRequest().Request.URI().QueryArgs().Peek(param))
		if token == "" {
			return "", errJWTMissing
		}
		return token, nil
	}
}

func jwtFromCookie(name string) tokenGetter {
	return func(c filter.Context) (string, error) {
		value := string(c.OriginRequest().Request.Header.Cookie(name))
		if len(value) == 0 {
			return "", errJWTMissing
		}
		return value, nil
	}
}
