package util

import (
	"github.com/spf13/viper"
)

// Config stores all configuration of the application.
// The values are read by viper from a config file or environment variable.
type Config struct {
	Environment   string `mapstructure:"ENVIRONMENT"`
	BitEnpoint    string `mapstructure:"BIT_ENPOINT"`
	BitAPIKey     string `mapstructure:"BIT_APIKEY"`
	GovSOCEnpoint string `mapstructure:"GOVSOC_ENPOINT"`

	OrganId      string `mapstructure:"ORGANID"`
	OrganName    string `mapstructure:"ORGANNAME"`
	OrganAdd     string `mapstructure:"ORGANADD"`
	OrganEmail   string `mapstructure:"ORGANEMAIL"`
	OrganPhone   string `mapstructure:"ORGANPONE"`
	OgranFax     string `mapstructure:"ORGANFAX"`
	OrganWebsite string `mapstructure:"ORGANWEBSITE"`
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
