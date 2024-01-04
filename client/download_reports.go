package client

import (
	"fmt"
	"github.com/rs/zerolog/log"
)

func (c *Client) DownloadReports(reportId string) error {
	errMsg := "download reports failed: : %w"
	_, err := c.R().
		SetOutput(fmt.Sprintf(`./temp/%s.zip`, reportId)).
		Get(fmt.Sprintf(`/api/v1.0/http/downloadReportZip?reportId=%s&allInstances=0`, reportId))
	log.Info().Msg(fmt.Sprintf(`ReportID: %s`, reportId))
	if err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}
