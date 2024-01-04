package client

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/go-resty/resty/v2"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const (
	errAuthFailed = "auth failed"
	errNotFound   = "api not found"
)

var ReportsRoute string
var NetworkRoute string

type Client struct {
	*resty.Client
	*tgbotapi.BotAPI
}

type Resp struct {
	Msg string
}

func NewBitClient(mode string, host string, secret string, botToken string) (*Client, error) {

	c := resty.New().
		SetBaseURL(host).
		SetHeader("Content-Type", "application/json")

	if mode == "onPremises" {
		c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		ReportsRoute = "/api/v1.0/jsonrpc/reports/computers"
		NetworkRoute = "/api/v1.0/jsonrpc/network/computers"
	} else if mode == "cloud" {
		ReportsRoute = "/api/v1.0/jsonrpc/reports"
		NetworkRoute = "/api/v1.0/jsonrpc/network"
	} else {
		err := errors.New("must declare mode as either onPremises or cloud in config.env")
		return nil, err
	}

	if secret != "" {
		h := secret + ":"
		s := base64.StdEncoding.EncodeToString([]byte(h))
		c.SetAuthScheme("Basic")
		c.SetAuthToken(s)
	}
	c.OnAfterResponse(func(c *resty.Client, res *resty.Response) error {
		var e string
		switch {
		case res.StatusCode() == 404:
			e = errNotFound
		case res.StatusCode() == 401:
			e = errAuthFailed
		case res.IsError():
			e = string(res.Body())
		}
		if e != "" {
			return errors.New(e)
		}
		return nil
	})
	bot, err := tgbotapi.NewBotAPI(botToken)

	if err != nil {
		return nil, err
	}
	return &Client{c, bot}, nil
}
