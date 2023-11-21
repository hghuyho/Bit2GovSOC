package main

import (
	"Bit2GovSOC/client"
	"Bit2GovSOC/util"
	"github.com/rs/zerolog/log"
)

func main() {
	config, err := util.LoadConfig(".")
	if err != nil {
		log.Fatal().Err(err).Msg("cannot load config")
	}

	c := client.NewClient(config.BitEnpoint, config.BitAPIKey)

	malwareStatusReportID, err := c.GetReportsListMalwareStatus()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot get reports list")
	}
	if err := c.DownloadReports(malwareStatusReportID); err != nil {
		log.Fatal().Err(err).Msg("cannot download report")
	}

	//enpointStatusReportID, _ := c.GetReportsListEnpointStatus()
	//fmt.Println(c.GetDownloadLinks(enpointStatusReportID))
	//networkIncidentsReportID, _ := c.GetReportsListNetworkIncidents()
	//fmt.Println(c.GetDownloadLinks(networkIncidentsReportID))
}
