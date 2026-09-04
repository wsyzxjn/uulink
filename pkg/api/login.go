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
	user, err := c.GetUserInfo()
	if err != nil {
		return nil, err
	}
	state := &LoginState{Raw: user.Raw}
	state.UserID = user.UserID
	state.Nickname = user.Nickname
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
