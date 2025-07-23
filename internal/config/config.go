package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type Config struct {
	SecretKey  string `mapstructure:"secret_key"`
	Env        string `mapstructure:"env"`
	HttpServer `mapstructure:"http_server"`
	Database   `mapstructure:"database"`
	WebHook `mapstructure:"webhook"
`
}

type HttpServer struct {
	Address string `mapstructure:"address" env-default:"8080"`
}

type Database struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
}

type WebHook struct {
	Url string `mapstructure:"url"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config

	viper.SetConfigFile(path)

	if err := viper.ReadInConfig(); err != nil {
		return cfg, fmt.Errorf("error reading config file: %w", err)
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, fmt.Errorf("error unmarshal config")
	}

	return cfg, nil
}
