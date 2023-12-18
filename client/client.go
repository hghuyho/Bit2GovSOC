package client

import (
	"encoding/base64"
	"errors"
	"github.com/go-resty/resty/v2"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const (
	errAuthFailed = "auth failed"
	errNotFound   = "api not found"
)

const (
	ReportsRoute = "/api/v1.0/jsonrpc/reports"
	NetworkRoute = "/api/v1.0/jsonrpc/network"
)

type Client struct {
	*resty.Client
	*tgbotapi.BotAPI
}

type Resp struct {
	Msg string
}

func NewBitClient(host string, secret string, botToken string) (*Client, error) {
	c := resty.New().
		SetBaseURL(host).
		SetHeader("Content-Type", "application/json")

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
