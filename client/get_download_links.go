package client

import "fmt"

type GetDownloadLinksResp struct {
	ID      string `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Result  struct {
		ReadyForDownload bool   `json:"readyForDownload"`
		LastInstanceURL  string `json:"lastInstanceUrl"`
		AllInstancesURL  string `json:"allInstancesUrl"`
	} `json:"result"`
}

func (c *Client) GetDownloadLinks(reportId string) (string, error) {
	errMsg := "get reports download links failed: : %w"
	requestBody := fmt.Sprintf(`{ "params": {"reportId": "%s"},"jsonrpc": "2.0","method": "getDownloadLinks","id": "787b5e36-89a8-4353-88b9-6b7a32e9c87g"}`, reportId)
	res, err := c.R().SetBody(requestBody).
		SetResult(&GetDownloadLinksResp{}).
		Post(ReportsRoute)
	if err != nil {
		return "", fmt.Errorf(errMsg, err)
	}
	return res.Result().(*GetDownloadLinksResp).Result.LastInstanceURL, nil
}
