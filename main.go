package main

import (
	"Bit2GovSOC/client"
	"Bit2GovSOC/report"
	"Bit2GovSOC/util"
	"fmt"
	"github.com/rs/zerolog/log"
)

func main() {
	config, err := util.LoadConfig(".")
	if err != nil {
		log.Fatal().Err(err).Msg("cannot load config")
	}

	c := client.NewClient(config.BitEnpoint, config.BitAPIKey)
	malware, _ := report.ParsingMalware(c)
	fmt.Println(malware)

	// enpointStatusReportID, _ := c.GetReportsListEnpointStatus()
	// fmt.Println(c.GetDownloadLinks(enpointStatusReportID))
	// networkIncidentsReportID, _ := c.GetReportsListNetworkIncidents()
	// fmt.Println(c.GetDownloadLinks(networkIncidentsReportID))
}
