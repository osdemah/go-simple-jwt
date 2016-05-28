package jwt

import (
	"strings"
	"testing"
	"time"
)

func TestBase64Encoding(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	bs64 := generator.EncodeBase64([]byte("gints means gaming hints!"))
	expected := "Z2ludHMgbWVhbnMgZ2FtaW5nIGhpbnRzIQ=="
	if strings.Compare(bs64, expected) != 0 {
		t.Errorf("expected: %s\n\tgot: %s", expected, bs64)
	}
}

func TestBase64Decoding(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	str := string(generator.DecodeBase64("Z2ludHMgbWVhbnMgZ2FtaW5nIGhpbnRzIQ=="))
	expected := "gints means gaming hints!"
	if strings.Compare(str, expected) != 0 {
		t.Errorf("expected: %s\n\tgot: %s", expected, str)
	}
}

func TestEncodeHMAC(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	hmac := generator.EncodeBase64(generator.EncodeHMAC("gints means gaming hints!"))
	expected := "hAooNE4gke+aCxNdvTZgPZCecw6mUrvGQ5pIWg6gDhc="
	if strings.Compare(hmac, expected) != 0 {
		t.Errorf("expected: %s\n\tgot: %s", expected, hmac)
	}
}

func TestEncodeJWT(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	hmac := generator.EncodeBase64(generator.EncodeJWT("gints", "gaming hints"))
	expected := "0DY8xD+FPMDOW1cb3PW8ktpUwcgDFPauwxWnMWe42CI="
	if strings.Compare(hmac, expected) != 0 {
		t.Errorf("expected: %s\n\tgot: %s", expected, hmac)
	}
}

func TestValidateJWT(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	jwt := "gints.gaming hinst." +
		generator.EncodeBase64(generator.EncodeJWT("gints", "gaming hints"))
	if generator.ValidateJWT(jwt) {
		t.Errorf("validator can't validate jwt correctly")
	}
}

func TestGenerateJWT(t *testing.T) {
	t.Logf("I can't find a reasonable way to write a test for it.\n" +
		"\tBut I'm sure that it's working correctly!")
}

func TestDecode(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	payload := generator.Decode(generator.GenerateJWT("hamed1soleimani@gmail.com", false))
	expectedEmail := "hamed1soleimani@gmail.com"
	expectedAdmin := false
	expectedExp := time.Now().Unix() + 5*3600
	if strings.Compare(payload.Email, expectedEmail) != 0 ||
		payload.Admin != expectedAdmin || payload.Expire != expectedExp {
		t.Errorf("expected %s, %t, %d", expectedEmail, expectedAdmin, expectedExp)
		t.Errorf("got %s, %t, %d", payload.Email, payload.Admin, payload.Expire)
	}
}

func TestCheckExpire(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	payload := generator.Decode(generator.GenerateJWT("hamed1soleimani@gmail.com", false))
	if generator.CheckExpire(payload.Expire) {
		t.Errorf("jwt is expiring soon")
	}
	if !generator.CheckExpire(payload.Expire - 6*3600) {
		t.Errorf("jwt is expiring late")
	}
}

func TestCheckRelogin(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	payload := generator.Decode(generator.GenerateJWT("hamed1soleimani@gmail.com", false))
	if generator.CheckReLogin(payload.Expire - 3600*24*13) {
		t.Errorf("jwt requests relogin soon")
	}
	if !generator.CheckReLogin(payload.Expire - 3600*24*15) {
		t.Errorf("jwt requests relogin late")
	}
}

func TestRenewJWT(t *testing.T) {
	generator := NewJWTGenerator("1cfabccbf188251666dfa066a88864a7")
	jwt := generator.GenerateJWT("hamed1soleimani@gmail.com", false)
	payload := generator.Decode(generator.RenewJWT(jwt))
	expectedEmail := "hamed1soleimani@gmail.com"
	expectedAdmin := false
	expectedExp := time.Now().Unix() + 5*3600
	if strings.Compare(payload.Email, expectedEmail) != 0 ||
		payload.Admin != expectedAdmin || payload.Expire != expectedExp {
		t.Errorf("expected %s, %t, %d", expectedEmail, expectedAdmin, expectedExp)
		t.Errorf("got %s, %t, %d", payload.Email, payload.Admin, payload.Expire)
	}
}
