package client

import "fmt"

type ReportsListResp struct {
	ID      string `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Result  struct {
		Total      int `json:"total"`
		Page       int `json:"page"`
		PerPage    int `json:"perPage"`
		PagesCount int `json:"pagesCount"`
		Items      []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Type       int    `json:"type"`
			Occurrence int    `json:"occurrence"`
		} `json:"items"`
	} `json:"result"`
}

func (c *Client) GetReportsListEnpointStatus() (string, error) {
	errMsg := "get reports list failed: : %w"
	requestBody := `{"params": {"type": 7}, "jsonrpc": "2.0","method": "getReportsList","id": "787b5e36-89a8-4353-88b9-6b7a32e9c87f"}`

	res, err := c.R().SetBody(requestBody).
		SetResult(&ReportsListResp{}).
		Post(ReportsRoute)
	if err != nil {
		return "", fmt.Errorf(errMsg, err)
	}
	if res.Result().(*ReportsListResp).Result.Total > 1 {
		return "", fmt.Errorf(errMsg, err)
	}
	return res.Result().(*ReportsListResp).Result.Items[0].ID, nil
}

func (c *Client) GetReportsListMalwareStatus() (string, error) {
	errMsg := "get reports list failed: : %w"
	requestBody := `{"params": {"type": 12}, "jsonrpc": "2.0","method": "getReportsList","id": "787b5e36-89a8-4353-88b9-6b7a32e9c87f"}`
	res, err := c.R().SetBody(requestBody).
		SetResult(&ReportsListResp{}).
		Post(ReportsRoute)
	if err != nil {
		return "", fmt.Errorf(errMsg, err)
	}
	if res.Result().(*ReportsListResp).Result.Total > 1 {
		return "", fmt.Errorf(errMsg, err)
	}
	return res.Result().(*ReportsListResp).Result.Items[0].ID, nil
}

func (c *Client) GetReportsListNetworkIncidents() (string, error) {
	errMsg := "get reports list failed: : %w"
	requestBody := `{"params": {"type": 34}, "jsonrpc": "2.0","method": "getReportsList","id": "787b5e36-89a8-4353-88b9-6b7a32e9c87f"}`
	res, err := c.R().SetBody(requestBody).
		SetResult(&ReportsListResp{}).
		Post(ReportsRoute)
	if err != nil {
		return "", fmt.Errorf(errMsg, err)
	}
	if res.Result().(*ReportsListResp).Result.Total > 1 {
		return "", fmt.Errorf(errMsg, err)
	}
	return res.Result().(*ReportsListResp).Result.Items[0].ID, nil
}
