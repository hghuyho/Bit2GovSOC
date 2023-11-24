package report

import (
	"Bit2GovSOC/client"
	"archive/zip"
	"fmt"
	"github.com/dimchansky/utfbom"
	"github.com/gocarina/gocsv"
	"github.com/rs/zerolog/log"
	"io"
	"strings"
)

type Network struct {
	EndpointName    string `csv:"Endpoint Name"`
	EndpointIP      string `csv:"Endpoint IP"`
	EndpointFQDN    string `csv:"Endpoint FQDN"`
	Label           string `csv:"Label"`
	User            string `csv:"User"`
	URL             string `csv:"URL"`
	DetectionName   string `csv:"Detection Name"`
	AttackTechnique string `csv:"Attack Technique"`
	Attempts        string `csv:"Attempts"`
	AttackersIP     string `csv:"Attacker's IP"`
	TargetedIP      string `csv:"Targeted IP"`
	Port            string `csv:"Port"`
	LastBlocked     string `csv:"Last Blocked"`
}

func ParsingNetwork(c *client.Client) ([]Network, error) {
	var records []Network
	networkIncidentsReportID, err := c.GetReportsListNetworkIncidents()
	if err != nil {
		return nil, err
	}
	if err := c.DownloadReports(networkIncidentsReportID); err != nil {
		return nil, err
	}

	zipFileName := fmt.Sprintf(`./temp/%s.zip`, networkIncidentsReportID)
	// Read the zip file
	zipFile, err := zip.OpenReader(zipFileName)
	if err != nil {
		return nil, err
	}
	defer zipFile.Close()
	for _, f := range zipFile.File {
		// Check if the file is a CSV file
		if !strings.HasSuffix(f.Name, ".csv") {
			continue
		}
		// Open the CSV file
		csvFile, err := f.Open()
		if err != nil {
			log.Fatal().Err(err)
		}
		gocsv.SetCSVReader(func(in io.Reader) gocsv.CSVReader {
			return gocsv.LazyCSVReader(in)
		})

		defer csvFile.Close()
		if err := gocsv.Unmarshal(utfbom.SkipOnly(csvFile), &records); err != nil {
			log.Printf("Error reading CSV from %s: %v", f.Name, err)
			continue // Skip to the next file on error
		}
	}
	return records, nil
}
