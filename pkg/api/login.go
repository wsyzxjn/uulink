package api

import "fmt"

// LoginState describes whether the configured user JWT can currently access
// user-scoped APIs.
type LoginState struct {
	Valid    bool
	UserID   string
	Nickname string
	Raw      map[string]any
}

// GetLoginState validates the configured JWT by fetching user info. A response
// with code 0 but no user_id is treated as an invalid login state, matching the
// server's observed behavior for expired tokens.
func (c *Client) GetLoginState() (*LoginState, error) {
	resp, err := c.GetUserInfo()
	if err != nil {
		return nil, err
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		message, _ := resp["msg"].(string)
		return nil, &ResponseError{Code: int(code), Message: message, Response: resp}
	}

	state := &LoginState{Raw: resp}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return state, nil
	}
	state.UserID, _ = data["user_id"].(string)
	state.Nickname, _ = data["nickname"].(string)
	state.Valid = state.UserID != ""
	return state, nil
}

// JWTSubject returns the subject claim from an unverified JWT. UULink tokens
// are signed by the server and are validated through the API before use.
func JWTSubject(token string) (string, error) {
	subject, _, err := jwtClaims(token)
	if err != nil {
		return "", fmt.Errorf("decode JWT: %w", err)
	}
	return subject, nil
}
