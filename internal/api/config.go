package api

var loadedConfig *Config

type Config struct {
	IsOracle             bool
	OracleType           string
	OracleDbPath         string
	OracleAddress        string
	ServerKeyPath        string
	ClientKeyPath        string
	PublicKeyPath        string
	OraclePrivateKeyPath string
	OraclePublicKeyPath  string
	HomeDir              *string
}

func GetConfig() *Config {
	return loadedConfig
}

func SetConfig(config Config) {
	loadedConfig = &config
}
