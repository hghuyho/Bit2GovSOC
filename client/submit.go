package client

import "fmt"

func (c *Client) SubmitReports(GovSOCEnpoint string, xmlData []byte) (string, error) {
	errMsg := "submit reports failed: : %w"
	rsp, err := c.R().
		SetHeader("Content-Type", "text/xml").
		SetBody(xmlData).
		Post(GovSOCEnpoint)

	if err != nil {
		return "error", fmt.Errorf(errMsg, err)
	}
	return rsp.String(), nil
}
