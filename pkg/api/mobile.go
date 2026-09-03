package api

import (
	"fmt"
)

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
	if code, ok := resp["code"].(float64); ok && code != 0 {
		message, _ := resp["msg"].(string)
		return nil, &ResponseError{Code: int(code), Message: message, Response: resp}
	}
	return resp, nil
}

// LoginByMobile exchanges a mobile number and SMS verification code for a user JWT.
func (c *Client) LoginByMobile(countryCode, mobile, code string) (map[string]any, error) {
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
	if codeNum, ok := resp["code"].(float64); ok && codeNum != 0 {
		message, _ := resp["msg"].(string)
		return nil, &ResponseError{Code: int(codeNum), Message: message, Response: resp}
	}
	return resp, nil
}
