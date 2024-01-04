package client

import (
	"fmt"
)

type NetworkInventoryItems struct {
	ID      string `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Result  struct {
		Total      int `json:"total"`
		Page       int `json:"page"`
		PerPage    int `json:"perPage"`
		PagesCount int `json:"pagesCount"`
		Items      []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Type      int    `json:"type"`
			ParentID  string `json:"parentId"`
			CompanyID string `json:"companyId"`
			Details   struct {
				Label                  string   `json:"label"`
				Fqdn                   string   `json:"fqdn"`
				GroupID                string   `json:"groupId"`
				IsManaged              bool     `json:"isManaged"`
				MachineType            int      `json:"machineType"`
				OperatingSystemVersion string   `json:"operatingSystemVersion"`
				IP                     string   `json:"ip"`
				Macs                   []string `json:"macs"`
				Ssid                   string   `json:"ssid"`
				ManagedWithBest        bool     `json:"managedWithBest"`
				Policy                 struct {
					ID      string `json:"id"`
					Name    string `json:"name"`
					Applied bool   `json:"applied"`
				} `json:"policy"`
				Modules struct {
					Antimalware           bool `json:"antimalware"`
					Firewall              bool `json:"firewall"`
					ContentControl        bool `json:"contentControl"`
					PowerUser             bool `json:"powerUser"`
					DeviceControl         bool `json:"deviceControl"`
					AdvancedThreatControl bool `json:"advancedThreatControl"`
					ApplicationControl    bool `json:"applicationControl"`
					Encryption            bool `json:"encryption"`
					NetworkAttackDefense  bool `json:"networkAttackDefense"`
					AdvancedAntiExploit   bool `json:"advancedAntiExploit"`
					UserControl           bool `json:"userControl"`
					Antiphishing          bool `json:"antiphishing"`
					TrafficScan           bool `json:"trafficScan"`
					RemoteEnginesScanning bool `json:"remoteEnginesScanning"`
					RiskManagement        bool `json:"riskManagement"`
				} `json:"modules"`
				ProductOutdated bool `json:"productOutdated"`
			} `json:"details"`
			LastSuccessfulScan struct {
				Name string `json:"name"`
				Date string `json:"date"`
			} `json:"lastSuccessfulScan"`
		} `json:"items"`
	} `json:"result"`
}

func (c *Client) GetParentId() (string, error) {
	errMsg := "get reports list failed: : %w"
	requestBody := `{"params": {},"jsonrpc": "2.0","method": "getNetworkInventoryItems","id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"}`
	res, err := c.R().SetBody(requestBody).
		SetResult(&NetworkInventoryItems{}).
		Post(NetworkRoute)
	if err != nil {
		return "", fmt.Errorf(errMsg, err)
	}
	return res.Result().(*NetworkInventoryItems).Result.Items[0].ParentID, nil
}

func (c *Client) GetNetworkInventoryItems(i int, parentId string) (*NetworkInventoryItems, error) {
	errMsg := "get network inventory items failed: : %w"
	requestBody := fmt.Sprintf(`{ "params": {"parentId": "%s", "page": %d, "perPage": 100, "filters": {"type": { "computers": true},"depth": {"allItemsRecursively": true}},"options": {"companies": { "returnAllProducts": true},"endpoints": { "returnProductOutdated": true, "includeScanLogs": true }}}, "jsonrpc": "2.0", "method": "getNetworkInventoryItems","id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"}`, parentId, i)

	res, err := c.R().SetBody(requestBody).
		SetResult(&NetworkInventoryItems{}).
		Post(NetworkRoute)
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}

	return res.Result().(*NetworkInventoryItems), nil
}

func (c *Client) GetNetworkInventoryItemsWithoutParentId(i int) (*NetworkInventoryItems, error) {
	errMsg := "get network inventory items without parentId failed: : %w"
	requestBody := fmt.Sprintf(`{ "params": {"page": %d, "perPage": 100, "filters": {"type": { "computers": true},"depth": {"allItemsRecursively": true}}}, "jsonrpc": "2.0", "method": "getNetworkInventoryItems","id": "tracking"}`, i)

	res, err := c.R().SetBody(requestBody).
		SetResult(&NetworkInventoryItems{}).
		Post(NetworkRoute)
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}

	return res.Result().(*NetworkInventoryItems), nil
}
