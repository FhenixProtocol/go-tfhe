package api

var loadedConfig *Config

type Config struct {
	IsOracle             bool    `koanf:"is-oracle"`
	OracleType           string  `koanf:"oracle-type"`
	OracleDbPath         string  `koanf:"oracle-db-path"`
	OracleAddress        string  `koanf:"oracle-address"`
	ServerKeyPath        string  `koanf:"server-key-path"`
	ClientKeyPath        string  `koanf:"client-key-path"`
	PublicKeyPath        string  `koanf:"public-key-path"`
	OraclePrivateKeyPath string  `koanf:"oracle-private-key-path"`
	OraclePublicKeyPath  string  `koanf:"oracle-public-key-path"`
	HomeDir              *string `koanf:"home-dir"`
}

var ConfigDefault = Config{
	IsOracle:             true,
	OracleType:           "local",
	OracleDbPath:         "data/oracle.db",
	OracleAddress:        "http://127.0.0.1:9001",
	ServerKeyPath:        "keys/tfhe/sks",
	ClientKeyPath:        "keys/tfhe/cks",
	PublicKeyPath:        "keys/tfhe/pks",
	OraclePrivateKeyPath: "keys/oracle/private-oracle.key",
	OraclePublicKeyPath:  "keys/oracle/public-oracle.key",
}

func GetConfig() *Config {
	return loadedConfig
}

func SetConfig(config Config) {
	loadedConfig = &config
}
