package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Iface             string    `json:"interface" mapstructure:"interface"`
	Pcap              string    `json:"pcapfile" mapstructure:"pcapfile"`
	BPF               string    `json:"bpf" mapstructure:"bpf"`
	Snaplen           int       `json:"snaplength" mapstructure:"snaplength"`
	Buffersize        int       `json:"buffersize" mapstructure:"buffersize"`
	Fangrp            int       `json:"fangroup" mapstructure:"fangroup"`
	Capthreads        int       `json:"capturethreads" mapstructure:"capturethreads"`
	Unidir            bool      `json:"unidirectional" mapstructure:"unidirectional"`
	Rollover          string    `json:"rollover" mapstructure:"rollover"`
	Printtime         string    `json:"printtime" mapstructure:"printtime"`
	Cachetime         string    `json:"cachetime" mapstructure:"cachetime"`
	CXTtimeout        string    `json:"cxttimeout" mapstructure:"cxttimeout"`
	Logfile           string    `json:"logfile" mapstructure:"logfile"`
	Cache             bool      `json:"cache" mapstructure:"cache"`
	Loglevel          string    `json:"loglevel" mapstructure:"loglevel"`
	LogFormat         string    `json:"logformat" mapstructure:"logformat"`
	ChannelBufferSize int       `json:"channelbuffersize" mapstructure:"channelbuffersize"` // New
	Shutdown          chan bool `json:"-" mapstructure:"-"`
	Stop              chan bool `json:"-" mapstructure:"-"`
}

var C *Config

func LoadConfig() *Config {
	// 1. Set Default Values
	viper.SetDefault("capturethreads", 1)
	viper.SetDefault("fangroup", 42)
	viper.SetDefault("interface", "any")
	viper.SetDefault("pcapfile", "")
	viper.SetDefault("bpf", "((ip) or vlan) and port 53")
	viper.SetDefault("snaplength", 1508)
	viper.SetDefault("buffersize", 16) // MB
	viper.SetDefault("unidirectional", false)
	viper.SetDefault("cache", true)
	viper.SetDefault("rollover", "1G")
	viper.SetDefault("printtime", "12h")
	viper.SetDefault("cachetime", "6h")
	viper.SetDefault("cxttimeout", "60s")
	viper.SetDefault("logfile", "/var/log/passivednsgo.json")
	viper.SetDefault("loglevel", "INFO")
	viper.SetDefault("logformat", "json")
	viper.SetDefault("channelbuffersize", 10000) // Default buffer size

	// 2. Define Command Line Flags
	pflag.String("config", "", "Path to configuration file (optional)")
	pflag.Int("capturethreads", 1, "Number of threads for capturing packets")
	pflag.Int("fangroup", 42, "Fanout group ID")
	pflag.String("interface", "any", "Interface to capture packets from")
	pflag.String("pcapfile", "", "Pcap file to process")
	pflag.String("bpf", "((ip) or vlan) and port 53", "Berkley packet filter!")
	pflag.Int("snaplength", 1508, "Snaplen, if <= 0, use 65535")
	pflag.Int("buffersize", 16, "Interface buffersize (MB)")
	pflag.Bool("unidirectional", false, "Output unidirectional (no caching)")
	pflag.Bool("cache", true, "Enable caching and aggregate output (on bidirectional output)")
	pflag.String("rollover", "1G", "Log rollover size M/G/T (1G)")
	pflag.String("printtime", "12h", "Print cached objects each printtime")
	pflag.String("cachetime", "6h", "Delete object from cache if no updates during cachetime")
	pflag.String("cxttimeout", "60s", "TCP and UDP connection timeout")
	pflag.String("logfile", "/var/log/passivednsgo.json", "PassiveDNS DNS log file")
	pflag.String("loglevel", "INFO", "Log Level [ERROR|WARN|INFO|DEBUG] (Default: INFO)")
	pflag.String("logformat", "json", "Log Format [json|text] (Default: json)")
	pflag.Int("channelbuffersize", 10000, "Channel buffer size")

	pflag.Parse()

	// 3. Bind Flags to Viper
	viper.BindPFlag("capturethreads", pflag.Lookup("capturethreads"))
	viper.BindPFlag("fangroup", pflag.Lookup("fangroup"))
	viper.BindPFlag("interface", pflag.Lookup("interface"))
	viper.BindPFlag("pcapfile", pflag.Lookup("pcapfile"))
	viper.BindPFlag("bpf", pflag.Lookup("bpf"))
	viper.BindPFlag("snaplength", pflag.Lookup("snaplength"))
	viper.BindPFlag("buffersize", pflag.Lookup("buffersize"))
	viper.BindPFlag("unidirectional", pflag.Lookup("unidirectional"))
	viper.BindPFlag("cache", pflag.Lookup("cache"))
	viper.BindPFlag("rollover", pflag.Lookup("rollover"))
	viper.BindPFlag("printtime", pflag.Lookup("printtime"))
	viper.BindPFlag("cachetime", pflag.Lookup("cachetime"))
	viper.BindPFlag("cxttimeout", pflag.Lookup("cxttimeout"))
	viper.BindPFlag("logfile", pflag.Lookup("logfile"))
	viper.BindPFlag("loglevel", pflag.Lookup("loglevel"))
	viper.BindPFlag("logformat", pflag.Lookup("logformat"))
	viper.BindPFlag("channelbuffersize", pflag.Lookup("channelbuffersize"))

	// 4. Load Config File
	cfgFile, _ := pflag.CommandLine.GetString("config")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/passivednsgo/")
		viper.AddConfigPath(".")
		viper.SetConfigName("passivednsgo")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("PASSIVEDNS")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Printf("Error reading config file: %s\n", err)
		}
	} else {
		fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		fmt.Printf("Unable to decode config into struct: %v\n", err)
	}

	cfg.Shutdown = make(chan bool, 1)
	cfg.Stop = make(chan bool, 1)

	C = &cfg
	return C
}
