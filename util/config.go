package util

import (
	"github.com/spf13/viper"
)

// Config stores all configuration of the application.
// The values are read by viper from a config file or environment variable.
type Config struct {
	Mode           string `mapstructure:"MODE"`
	BitEnpoint     string `mapstructure:"BIT_ENPOINT"`
	BitAPIKey      string `mapstructure:"BIT_APIKEY"`
	GovSOCEnpoint  string `mapstructure:"GOVSOC_ENPOINT"`
	BotToken       string `mapstructure:"TG_BOT_TOKEN"`
	GroupID        int64  `mapstructure:"TG_GROUP_ID"`
	OrganId        string `mapstructure:"ORGANID"`
	OrganName      string `mapstructure:"ORGANNAME"`
	OrganAdd       string `mapstructure:"ORGANADD"`
	OrganEmail     string `mapstructure:"ORGANEMAIL"`
	OrganPhone     string `mapstructure:"ORGANPONE"`
	OgranFax       string `mapstructure:"ORGANFAX"`
	OrganWebsite   string `mapstructure:"ORGANWEBSITE"`
	NCSCSkipVerify bool   `mapstructure:"NCSC_SKIPVERIFY" default:"false"`
	BitSkipVerify  bool   `mapstructure:"BIT_SKIPVERIFY" default:"false"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
