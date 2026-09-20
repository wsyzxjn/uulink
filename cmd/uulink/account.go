package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
)

func doListDevices(client *api.Client) error {
	devices, err := client.GetDeviceList()
	if err != nil {
		return fmt.Errorf("get device list: %w", err)
	}

	fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n", "DEVICE_ID", "NAME", "STATUS", "PLAT", "CLIENT_ID", "VERSION")
	fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n", "--------", "----", "------", "----", "---------", "-------")
	for _, device := range devices {
		fmt.Printf("%-24s %-16s %-14s %-8d %-12s %s\n",
			device.DeviceID, device.Alias, device.Status, device.Platform, device.ClientID, device.VersionName)
	}
	return nil
}

func doUserInfo(client *api.Client) error {
	user, err := client.GetUserInfo()
	if err != nil {
		return fmt.Errorf("get user info: %w", err)
	}
	logging.Infof("user info: nickname=%q user_id_len=%d keys=%v",
		user.Nickname, len(user.UserID), mapKeys(user.Raw))
	return nil
}

func doInteractiveLogin(client *api.Client, cfg *auth.Config, configPath string, qrTimeout time.Duration, defaultCountryCode string) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Select login method:")
	fmt.Println("  1. QR code scan (Recommended)")
	fmt.Println("  2. SMS verification code (Mobile)")
	fmt.Print("Enter choice [1/2, default 1]: ")
	choiceText, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read login method: %w", err)
	}
	choice := strings.TrimSpace(choiceText)
	switch choice {
	case "2", "mobile", "sms":
		return doMobileLogin(client, cfg, configPath, defaultCountryCode, "")
	default:
		return doLoginQRCode(client, cfg, configPath, qrTimeout)
	}
}

func doMobileLogin(client *api.Client, cfg *auth.Config, configPath, countryCode, mobile string) error {
	reader := bufio.NewReader(os.Stdin)
	if mobile == "" {
		fmt.Print("Enter mobile phone number: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read mobile number: %w", err)
		}
		mobile = strings.TrimSpace(text)
		if mobile == "" {
			return fmt.Errorf("mobile phone number cannot be empty")
		}
	}
	if countryCode == "" {
		countryCode = "+86"
	}

	logging.Infof("requesting SMS verification code for %s %s...", countryCode, mobile)
	resp, err := client.RequestMobileCode(countryCode, mobile)
	if err != nil {
		var responseErr *api.ResponseError
		if errors.As(err, &responseErr) {
			return fmt.Errorf("request SMS code failed: code=%d msg=%q (server may require captcha): %w",
				responseErr.Code, responseErr.Message, err)
		}
		return fmt.Errorf("request SMS code: %w", err)
	}
	logging.Infof("SMS code request sent (code=%v msg=%q)", resp["code"], resp["msg"])

	fmt.Print("Enter SMS verification code: ")
	codeText, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read SMS code: %w", err)
	}
	code := strings.TrimSpace(codeText)
	if code == "" {
		return fmt.Errorf("verification code cannot be empty")
	}

	login, err := client.LoginByMobile(countryCode, mobile, code)
	if err != nil {
		var responseErr *api.ResponseError
		if errors.As(err, &responseErr) {
			return fmt.Errorf("mobile login failed: code=%d msg=%q: %w", responseErr.Code, responseErr.Message, err)
		}
		return fmt.Errorf("mobile login: %w", err)
	}

	token := login.Token
	refreshedState, err := persistLogin(client, cfg, configPath, token)
	if err != nil {
		return err
	}
	logging.Infof("mobile login confirmed; JWT length=%d user_id_len=%d config=%s",
		len(token), len(refreshedState.UserID), configPath)
	return nil
}

func persistLogin(client *api.Client, cfg *auth.Config, configPath, token string) (*api.LoginState, error) {
	userID, err := api.JWTSubject(token)
	if err != nil {
		return nil, fmt.Errorf("decode login JWT: %w", err)
	}

	previousJWT, previousUserID, previousGuestID := cfg.JWT, cfg.UserID, cfg.GuestID
	cfg.JWT = token
	cfg.UserID = userID
	cfg.GuestID = ""
	state, err := client.GetLoginState()
	if err != nil || !state.Valid {
		cfg.JWT, cfg.UserID, cfg.GuestID = previousJWT, previousUserID, previousGuestID
		if err != nil {
			return nil, fmt.Errorf("validate refreshed login state: %w", err)
		}
		return nil, fmt.Errorf("refreshed login state is invalid")
	}
	if err := auth.SaveConfigFile(configPath, cfg); err != nil {
		cfg.JWT, cfg.UserID, cfg.GuestID = previousJWT, previousUserID, previousGuestID
		return nil, fmt.Errorf("save refreshed config: %w", err)
	}
	return state, nil
}

func doRefreshLogin(client *api.Client, cfg *auth.Config, configPath string, timeout time.Duration) error {
	state, err := client.GetLoginState()
	if err == nil && state.Valid {
		logging.Infof("login state valid; no refresh needed (user_id_len=%d nickname=%q)",
			len(state.UserID), state.Nickname)
		return nil
	}
	if err != nil {
		var responseErr *api.ResponseError
		if !errors.As(err, &responseErr) {
			return fmt.Errorf("validate login state: %w", err)
		}
		logging.Infof("login state invalid: %v", responseErr)
	} else {
		logging.Infof("login state invalid: user info response has no user_id")
	}
	return doLoginQRCode(client, cfg, configPath, timeout)
}

// ensureBootstrapGuest returns a guest session usable for account bootstrap
// calls such as QR-code login.
//
// POST /guest/create sends this machine's device_id, and the server rejects it
// with code 1001 when that device was never registered. A fresh config.json has
// no device_id, so fall back to registering an accountless device first and
// persist the identity, which keeps later runs on the cheap path.
func ensureBootstrapGuest(client *api.Client, cfg *auth.Config, configPath, name string) (*api.GuestSession, error) {
	if cfg.DeviceID != "" && cfg.ClientID != "" && (cfg.Platform == 1 || runtime.GOOS == "windows") {
		session, err := client.CreateGuest()
		if err == nil {
			return session, nil
		}
		logging.Debugf("guest create with configured identity failed, registering a device: %v", err)
	}
	session, identity, err := client.CreateUnboundGuest(name)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		cfg.ClientID = identity.ClientID
		cfg.DeviceID = identity.DeviceID
		cfg.Platform = 1
		if configPath != "" {
			if saveErr := auth.SaveConfigFile(configPath, cfg); saveErr != nil {
				logging.Warnf("could not persist the registered device identity: %v", saveErr)
			}
		}
	}
	return session, nil
}

// qrStatusRetryDelay spaces out status polls after a transport error.
const qrStatusRetryDelay = 2 * time.Second

func doLoginQRCode(client *api.Client, cfg *auth.Config, configPath string, timeout time.Duration) error {
	loginDeviceName, err := cfg.EffectiveHostname()
	if err != nil {
		return fmt.Errorf("resolve login device name: %w", err)
	}
	guest, err := ensureBootstrapGuest(client, cfg, configPath, loginDeviceName)
	if err != nil {
		return fmt.Errorf("create guest: %w", err)
	}
	info, err := client.GenerateQRCodeLoginWithGuest(guest)
	if err != nil {
		return fmt.Errorf("generate QR code login: %w", err)
	}
	logging.Infof("QR-code login URL: %s", info.QRCodeJumpURL)
	logging.Infof("bootstrap credentials: token_len=%d status_query_ticket_len=%d",
		len(info.Token), len(info.StatusQueryTicket))

	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("QR code login timed out after %s", timeout)
		}
		status, err := client.QRCodeLoginStatusWithGuest(guest, info)
		if err != nil {
			var responseErr *api.ResponseError
			if errors.As(err, &responseErr) {
				return fmt.Errorf("QR code login status failed: %w", responseErr)
			}
			// The status endpoint is a long poll, so a healthy loop never
			// spins; a transport error must not turn it into one.
			logging.Warnf("query QR code login status: %v; retrying in %s", err, qrStatusRetryDelay)
			time.Sleep(qrStatusRetryDelay)
			continue
		}
		logging.Infof("QR code login status: login_status=%d token_len=%d qrcode_jump_url_len=%d keys=%v",
			status.LoginStatus, len(status.Token), len(status.QRCodeJumpURL), mapKeys(status.Raw))
		if status.LoginStatus == 4 {
			login, err := client.LoginByQRCodeWithGuest(guest, info)
			if err != nil {
				return fmt.Errorf("QR code login exchange failed: %w", err)
			}
			token := login.Token
			refreshedState, err := persistLogin(client, cfg, configPath, token)
			if err != nil {
				return err
			}
			logging.Infof("QR code login confirmed; JWT length=%d user_id_len=%d config=%s",
				len(token), len(refreshedState.UserID), configPath)
			return nil
		}
		if status.Token != "" {
			logging.Infof("QR code scanned; waiting for login exchange confirmation")
		}
		if status.LoginStatus != 0 {
			logging.Infof("QR code scanned; waiting for login token")
		}
	}
}
