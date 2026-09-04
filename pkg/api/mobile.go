package api

import (
	"fmt"
)

// LoginResult is the credential returned by a successful user login.
type LoginResult struct {
	Token string
}

// RequestMobileCode sends an SMS verification code to the specified phone number.
func (c *Client) RequestMobileCode(countryCode, mobile string) (map[string]any, error) {
	if countryCode == "" {
		countryCode = "+86"
	}
	body := map[string]any{
		"country_code": countryCode,
		"mobile":       mobile,
		"type":         "login",
	}
	resp, err := c.Do("POST", "/api/v1/security/mobile/code", body)
	if err != nil {
		return nil, fmt.Errorf("request mobile code: %w", err)
	}
	return resp, nil
}

// LoginByMobile exchanges a mobile number and SMS verification code for a user JWT.
func (c *Client) LoginByMobile(countryCode, mobile, code string) (*LoginResult, error) {
	if countryCode == "" {
		countryCode = "+86"
	}
	body := map[string]any{
		"country_code": countryCode,
		"mobile":       mobile,
		"code":         code,
	}
	resp, err := c.Do("POST", "/api/v1/login/by_mobile", body)
	if err != nil {
		return nil, fmt.Errorf("login by mobile: %w", err)
	}
	data, err := responseData(resp, "mobile login")
	if err != nil {
		return nil, err
	}
	token, _ := data["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("mobile login response has no token")
	}
	return &LoginResult{Token: token}, nil
}
