package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type JWTPayload struct {
	Admin  bool
	Email  string
	Expire int64
}

type JWTGenerator struct {
	Secret []byte
}

func NewJWTGenerator(secret string) *JWTGenerator {
	return &JWTGenerator{Secret: []byte(secret)}
}

func (generator *JWTGenerator) EncodeBase64(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func (generator *JWTGenerator) DecodeBase64(src string) []byte {
	dst, _ := base64.StdEncoding.DecodeString(src)
	return dst
}

func (generator *JWTGenerator) EncodeJWT(header string, payload string) []byte {
	return generator.EncodeHMAC(header + "." + payload)
}

func (generator *JWTGenerator) EncodeHMAC(src string) []byte {
	mac := hmac.New(sha256.New, generator.Secret)
	mac.Write([]byte(src))
	return mac.Sum(nil)
}

func (generator *JWTGenerator) ValidateJWT(src string) bool {
	jwt := strings.Split(src, ".")
	if len(jwt) != 3 {
		return false
	}
	return hmac.Equal(generator.DecodeBase64(jwt[2]),
		generator.EncodeJWT(jwt[0], jwt[1]))
}

func (generator *JWTGenerator) GenerateJWT(email string, admin bool) (jwt string) {
	header := make(map[string]string)
	payload := make(map[string]string)
	header["alg"] = "HS256"
	header["typ"] = "JWT"
	payload["mail"] = email
	payload["sub"] = "auth"
	now := time.Now().Unix()
	payload["exp"] = strconv.FormatInt(now+5*3600, 10)
	if admin {
		payload["admin"] = "1"
	} else {
		payload["admin"] = "0"
	}
	jsonHeader, _ := json.Marshal(header)
	jsonPayload, _ := json.Marshal(payload)
	bs64Header := generator.EncodeBase64(jsonHeader)
	bs64payload := generator.EncodeBase64(jsonPayload)
	bs64signature := generator.EncodeBase64(generator.EncodeJWT(bs64Header, bs64payload))
	jwt = bs64Header + "." + bs64payload + "." + bs64signature
	return
}

func (generator *JWTGenerator) RenewJWT(jwt string) (new string) {
	payload := generator.Decode(jwt)
	new = generator.GenerateJWT(payload.Email, payload.Admin)
	return
}

func (generator *JWTGenerator) CheckExpire(exp int64) (expire bool) {
	now := time.Now().Unix()
	expire = now > exp
	return
}

func (generator *JWTGenerator) CheckReLogin(exp int64) (relogin bool) {
	now := time.Now().Unix()
	relogin = now > exp+3600*24*14
	return
}

func (generator *JWTGenerator) Decode(jwt string) (payload JWTPayload) {
	bs64Payload := generator.DecodeBase64(strings.Split(jwt, ".")[1])
	mapPayload := make(map[string]string)
	json.Unmarshal(bs64Payload, &mapPayload)
	payload.Email = mapPayload["mail"]
	payload.Admin = mapPayload["admin"] == "1"
	payload.Expire, _ = strconv.ParseInt(mapPayload["exp"], 10, 64)
	return
}
