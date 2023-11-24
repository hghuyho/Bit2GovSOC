package main

import (
	"Bit2GovSOC/client"
	"Bit2GovSOC/report"
	"Bit2GovSOC/util"
	"encoding/xml"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type EdXMLEnvelope struct {
	XMLName     xml.Name    `xml:"edXMLEnvelope"`
	XMLNS       string      `xml:"xmlns:edXML,attr"`
	EdXMLHeader EdXMLHeader `xml:"edXML:edXMLHeader"`
	EdXMLBody   EdXMLBody   `xml:"edXML:edXMLBody"`
}

type EdXMLHeader struct {
	MessageHeader MessageHeader `xml:"edXML:MessageHeader"`
	Signature     Signature     `xml:"Signature"`
}

type MessageHeader struct {
	From    From   `xml:"edXML:From"`
	Subject string `xml:"Subject"`
}

type From struct {
	OrganId   string `xml:"edXML:OrganId"`
	OrganName string `xml:"edXML:OrganName"`
	OrganAdd  string `xml:"edXML:OrganAdd"`
	Email     string `xml:"edXML:Email"`
	Telephone string `xml:"edXML:Telephone"`
	Fax       string `xml:"edXML:Fax"`
	Website   string `xml:"edXML:Website"`
}

type Signature struct {
	XMLNS          string     `xml:"xmlns,attr"`
	SignedInfo     SignedInfo `xml:"SignedInfo"`
	SignatureValue string     `xml:"SignatureValue"`
	KeyInfo        KeyInfo    `xml:"KeyInfo"`
}

type SignedInfo struct {
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	Reference              Reference              `xml:"Reference"`
}

type CanonicalizationMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type Reference struct {
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:"Transforms"`
	DigestMethod DigestMethod `xml:"DigestMethod"`
	DigestValue  string       `xml:"DigestValue"`
}

type Transforms struct {
	Transform []Transform `xml:"Transform"`
}

type Transform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type KeyInfo struct {
	X509Data X509Data `xml:"X509Data"`
}

type X509Data struct {
	X509SubjectName string `xml:"X509SubjectName"`
	X509Certificate string `xml:"X509Certificate"`
}

type EdXMLBody struct {
	AVReport AVReport `xml:"AVReport"`
}

type AVReport struct {
	Name           string         `xml:"name,attr"`
	Datetime       string         `xml:"Datetime"`
	Malware        Malware        `xml:"Malware"`
	Connection     Connection     `xml:"Connection"`
	Vulnerability  Vulnerability  `xml:"Vulnerability"`
	OS             OS             `xml:"OS"`
	Update         Update         `xml:"Update"`
	QualityFeature QualityFeature `xml:"QualityFeature"`
}

type Malware struct {
	MachineMalware []MachineMalware `xml:"Machine"`
}

type MachineMalware struct {
	IP          string      `xml:"ip,attr"`
	Name        string      `xml:"name,attr"`
	MalwareInfo MalwareInfo `xml:"MalwareInfo"`
}

type MalwareInfo struct {
	MalwareName     string `xml:"MalwareName"`
	MalwareType     string `xml:"MalwareType"`
	MalwareBehavior string `xml:"MalwareBehavior"`
	TypeOfDevice    string `xml:"TypeOfDevice"`
	NumberFile      string `xml:"NumberFile"`
}

type Connection struct {
	MachineConnection []MachineConnection `xml:"Machine"`
}
type MachineConnection struct {
	IP             string         `xml:"ip,attr"`
	Name           string         `xml:"name,attr"`
	ConnectionInfo ConnectionInfo `xml:"ConnectionInfo"`
}

type ConnectionInfo struct {
	Program  string `xml:"Program"`
	MD5      string `xml:"md5"`
	Sha2     string `xml:"Sha2"`
	TargetIP string `xml:"TargetIP"`
}

type Vulnerability struct {
	MachineVulnerability MachineVulnerability `xml:"Machine"`
}

type MachineVulnerability struct {
	IP                string            `xml:"ip,attr"`
	Name              string            `xml:"name,attr"`
	VulnerabilityInfo VulnerabilityInfo `xml:"VulnerabilityInfo"`
}

type VulnerabilityInfo struct {
	Name   string `xml:"Name"`
	OSName string `xml:"OSName"`
}

type OS struct {
	MachineOS  MachineOS `xml:"Machine"`
	OSName     string    `xml:"OSName"`
	LastUpdate string    `xml:"LastUpdate"`
}
type MachineOS struct {
	IP   string `xml:"ip,attr"`
	Name string `xml:"name,attr"`
}
type Update struct {
	NumberMachineNotUpdateOn15Day string `xml:"NumberMachineNotUpdateOn15Day"`
}

type QualityFeature struct {
	MachineQualityFeature []MachineQualityFeature `xml:"Machine"`
}

type MachineQualityFeature struct {
	IP             string `xml:"ip,attr"`
	Name           string `xml:"name,attr"`
	AutoProtect    string `xml:"AutoProtect"`
	EnableFirewall string `xml:"EnableFirewall"`
}

func main() {
	// Prompt user to press Enter to start
	fmt.Print("Press Enter to start...")
	fmt.Scanln()

	currentTime := time.Now().Format("20060102150405")

	fmt.Println("Loading config...")
	config, err := util.LoadConfig(".")
	if err != nil {
		log.Fatal().Err(err).Msg("cannot load config")
	}

	c := client.NewBitClient(config.BitEnpoint, config.BitAPIKey)

	// Create an instance of EDXMLEnvelope
	e := EdXMLEnvelope{
		XMLNS: "http://www.mic.gov.vn/TBT/QCVN_102_2016",
		EdXMLHeader: EdXMLHeader{
			MessageHeader: MessageHeader{
				From: From{
					OrganId:   config.OrganId,
					OrganName: config.OrganName,
					OrganAdd:  config.OrganAdd,
					Email:     config.OrganEmail,
					Telephone: config.OrganPhone,
					Fax:       "",
					Website:   config.OrganWebsite,
				},
				Subject: "Test Report",
			},
			Signature: Signature{
				XMLNS: "http://www.w3.org/2000/09/xmldsig#",
				SignedInfo: SignedInfo{
					CanonicalizationMethod: CanonicalizationMethod{
						Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
					},
					SignatureMethod: SignatureMethod{
						Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
					},
					Reference: Reference{
						Transforms: Transforms{
							Transform: []Transform{
								{
									Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
								},
								{
									Algorithm: "http://www.w3.org/TR/xml-exc-c14n#",
								},
							},
						},
						DigestMethod: DigestMethod{
							Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
						},
						DigestValue: "PuRChYEMCsAVya7V39ybDhGodNKDo8OTQtOOUwtx4B5",
					},
				},

				SignatureValue: "FXM4QWgcX3EbOfdB+p50Kh9p4jhnc2rIzvun5+FR1Q2ruCC1XQKGMbupEq3qXpTXNxxHcD/euv+RFH2EgIbyhO7Ouj6lIW4z1fZAuVtOkMjbgVLjoTyy9xtqc+PXcmUO8vqX7oyzR7MLK5JCkIsDUDOPNIxD718kFFqqVfvhvb4RL466YBEh2m48gbDzkWizBis6sFHXzQH2OACc9ko39NPiPNfcKjG0f/q4/esbPPyzOUTcdRMW6+hTI6aPFb8jn/MSS43VE4TbiDJI11WkmULnLspC1MzTMEaKba5Cq7NvoIRif9E5NK316WYA7hponYI6kyLCdJxo0ZEtOnSPQr==",
				KeyInfo: KeyInfo{
					X509Data: X509Data{
						X509SubjectName: "CN=user05, L=Ha Noi, O=Ban Co yeu Chinh phu, OU=Cuc Quan ly Ky thuat Nghiep vu Mat Ma, OU=Trung tam chung thuc dien to chuyen dung Chinh phu, C=VN",
						X509Certificate: "MIIFqTCCBJGgAwIBAgIDLfAwMAOGCSqGSIb3DQEBBQUAMFYxCzAJBgNVBAYTA1ZOMROwGwYDVQQKDBRCYW4gQ28geWV1IENoaW5oIHBodTEoMCYGAlUEAwwfQ28gcXVhbiBjaHVuZyBOaHVjIHNvIENoaW5oIHBodTAeFw0xMTAOMTMwOTQyMzlaFw0xNjA0MTEw0TQyMzlaMIG7MQswCQYDVQQGEwJWTjE7MDkGAlUECwwyVHJ1bmcgdGFtIGNodW5nIHRodWMgZGllbiBOdSBjaHV5ZW4gZHVuZyBDaGluaCBwaHUxLjAsBgNVBAsMJUNlYyBRdWFuIGx5IEtSIHRodWFOIESnaG11cCB2dSBNYXQgTWExHTAbBgNVBAoMFEJhbiBDbyB5ZXUgQ2hpbmggcGh1MQ8wDQYDVQQHDAZIYSBOb2kxDzANBgNVBAMMBnVzZXIwNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMh/+mvm2ev1584elfzXElcfzTK5GuCmA9r74UkDfbiP+4MedIQ/k2pyL2mzM5Osbpx+0AeRBSOOxIrb2yVsKmKC8JSzub8JLUhbyvtnh5rFLphBPRAi+MNvSZXByWDKvGHt8NwPGspNsgL1AI0bmz0GksOxiRmiI6mo/7YWFKBUCTkYB9a/pnLofJeBy/zQ2ekw6oUF5CNJOt/MLXmP2s3AVdq4KR2PJ3xRiSUFKat9RBcgR5Qi+NbvuURsWnloYysWiyFMd6ifWSouoc0b/T33X1p+IVz6GaFfVwYQ299TEDVHqXQZg7KkfMenkQgyKe2jOIJBAI3pyLhcanS0t8CAwEAAa0CAhgwggIUMAkGAlUdEwQCMAAwCwYDVROPBAQDAgZAMCUGCWCGSAGG+EIBDQQYFhZVc2VyIFNpZ24gb2YgQ2hpbmggcGh1MBOGAlUdDgQWBBT7mk6fmUvl9ktMqjSzTsyIbRuIGTCB1QYDVROjBIGNMIGKgBQFMUDeNL6zj8DbbsVDDj4S92PGHKFvpG0wazELMAkGAlUEBhMCVk4xHTAbBgNVBAoMFEJhbiBDbyB5ZXUgQ2hpbmggcGh1MT0wOwYDVQQDDDRDbyBxdWFuIGNodW5nIHRodWMgc28gY2hleWVuIGR1bmcgQ2hpbmggcGhlIChSb290Q0EpggEEMBsGAlUdEQQUMBKBEHVzZXIwNUBjYS5nb3Yudm4wMgYJYIZIAYb4QgEEBCUWI2h0dHA6Ly9jYS5nb3Yudm4vcGtpL3BlYi9jcmwvY3AuY3JsMDIGCWCGSAGG+EIBAwQ1FiNodHRw0i8vY2EuZ292LnZuL3BraS9wdWIvY3JsL2NwLmNybDBjBgNVHR8EXDBaMCmgJ6AlhiNodHRw0i8vY2EuZ292LnZuL3BraS9wdWIvY3JsL2NwLmNybDAtoCugKYYnaHROcDovL3BlYi5jYS5nb3Yudm4vcGtpL3BlYi9jcmwvY3AuY3JsMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAYYWaHROcDovL29jc3AuY2EuZ292LnZuLzANBgkqhkiG9w0BAQUFAAOCAQEAbsHix/XUcD7i+p5ufYNVxxYk0J/guTxE6t9fbgPvMcpxQrUu9JpHmNkna/r/OvEm2plylaAb6ODHaC196nUl7pt6HBMJt80X36RDUpghnkmmc3C6XZwCBve8A45WByYv+FNIEDpNoGgjZ2T5wpwWnOw4d4Nnb5R4EZGZ7zKEu/nolVuH0gAM1KyVE1Qj3hEwHYbZDQH1sBXZURtmS89F33xcadMDny3ymoiPH9f7MMBSwmgDISnHCDgyBijJo3m9tQV2SeuLs6NxNWnFKkOWTISLrpTzEkbChYR1z4t/nIvJ7jOrwgRB+gWFxgYGj8HxcZMy8Xv9cy+f4Xdxxxxx==",
					},
				},
			},
		},
	}

	e.EdXMLBody.AVReport = AVReport{
		Name:     "Anti-Virus Name",
		Datetime: strconv.FormatInt(time.Now().Unix(), 10),
	}

	fmt.Println("Parsing Malware Status report...")
	malwares, err := report.ParsingMalware(c)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot parsing malware")
	}
	for _, malware := range malwares {
		e.EdXMLBody.AVReport.Malware.MachineMalware = append(e.EdXMLBody.AVReport.Malware.MachineMalware, MachineMalware{
			Name: malware.EndpointName,
			MalwareInfo: MalwareInfo{
				MalwareName:     malware.MalwareName,
				MalwareType:     malware.ThreatType,
				MalwareBehavior: malware.ThreatType,
				TypeOfDevice:    malware.FilePath,
				NumberFile:      "1",
			},
		})
	}
	fmt.Println("Parsing Network Incidents report...")
	networks, err := report.ParsingNetwork(c)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot parsing network")
	}
	for _, network := range networks {
		e.EdXMLBody.AVReport.Connection.MachineConnection = append(e.EdXMLBody.AVReport.Connection.MachineConnection, MachineConnection{
			Name: network.EndpointName,
			IP:   network.EndpointIP,
			ConnectionInfo: ConnectionInfo{
				Program:  network.DetectionName,
				TargetIP: network.TargetedIP,
			},
		})
	}
	fmt.Println("Parsing Endpoint Modules Status report...")
	endpoints, err := report.ParsingEndpoint(c)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot parsing endpoint")
	}
	for _, endpoint := range endpoints {
		e.EdXMLBody.AVReport.QualityFeature.MachineQualityFeature = append(e.EdXMLBody.AVReport.QualityFeature.MachineQualityFeature, MachineQualityFeature{
			Name:           endpoint.EndpointName,
			IP:             endpoint.IP,
			AutoProtect:    endpoint.Antimalware,
			EnableFirewall: endpoint.Firewall,
		})

	}
	// Encode the struct to XML
	xmlData, err := xml.MarshalIndent(e, "", "    ")
	if err != nil {
		log.Fatal().Err(err).Msg("error encoding to XML")
	}

	fmt.Println("Calling to " + config.GovSOCEnpoint)

	submitClient := resty.New()
	rsp, err := submitClient.R().
		SetHeader("Content-Type", "text/xml").
		SetBody(xmlData).
		Post(config.GovSOCEnpoint)

	if err != nil {
		log.Fatal().Err(err).Msg("submit reports failed")
	}
	fmt.Println("Response status: " + rsp.Status())

	// Generate a filename with the current datetime
	filename := fmt.Sprintf("./output/edxml-%s.xml", currentTime)
	// Create the output directory and any necessary parent directories
	outputDir := filepath.Dir(filename)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatal().Err(err).Msg("error creating output directory")
	}
	// Save the XML data to a file
	err = os.WriteFile(filename, xmlData, 0644)
	if err != nil {
		log.Fatal().Err(err).Msg("error saving XML to file")
	}
	fmt.Printf("XML data written to %s\n", filename)
	// Wait for Enter key before closing
	fmt.Println("Press Enter to exit...")
	fmt.Scanln()
}
