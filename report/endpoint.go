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

type EnpointModules struct {
	EndpointName          string `csv:"Endpoint Name"`
	EndpointFQDN          string `csv:"Endpoint FQDN"`
	IP                    string `csv:"IP"`
	Antimalware           string `csv:"Antimalware"`
	NetworkAttackDefense  string `csv:"Network Attack Defense"`
	AdvancedAntiExploit   string `csv:"Advanced Anti-Exploit"`
	Firewall              string `csv:"Firewall"`
	ContentControl        string `csv:"Content Control"`
	DeviceControl         string `csv:"Device Control"`
	PowerUser             string `csv:"Power User"`
	Exchange              string `csv:"Exchange"`
	AdvancedThreatControl string `csv:"Advanced Threat Control"`
	ScanMode              string `csv:"Scan Mode"`
}

type EnpointProtection struct {
	EndpointName string `csv:"Endpoint Name"`
	EndpointFQDN string `csv:"Endpoint FQDN"`
	IP           string `csv:"IP"`
	UpdateStatus string `csv:"Update Status"`
	LastUpdate   string `csv:"Last Update"`
	Antimalware  string `csv:"Antimalware"`
	Managed      string `csv:"Managed"`
	Online       string `csv:"Online"`
}

func ParsingEnpointModulesStatus(c *client.Client) ([]EnpointModules, error) {
	var records []EnpointModules
	endpointStatusReportID, err := c.GetReportsListEnpointModulesStatus()
	if err != nil {
		return nil, err
	}
	if err := c.DownloadReports(endpointStatusReportID); err != nil {
		return nil, err
	}

	zipFileName := fmt.Sprintf(`./temp/%s.zip`, endpointStatusReportID)
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

func ParsingEnpointProtectionStatus(c *client.Client) ([]EnpointProtection, error) {
	var records []EnpointProtection
	endpointStatusReportID, err := c.GetReportsListEndpointProtectionStatus()
	if err != nil {
		return nil, err
	}
	if err := c.DownloadReports(endpointStatusReportID); err != nil {
		return nil, err
	}

	zipFileName := fmt.Sprintf(`./temp/%s.zip`, endpointStatusReportID)
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
