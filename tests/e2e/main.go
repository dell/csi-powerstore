package main

import (
	"fmt"
	"log"

	e2e "github.com/dell/csi-powerstore/tests/e2e/testSuite"
	"github.com/spf13/viper"
)

type TestConfigEntry struct {
	TestConfig Entry
}

type Entry struct {
	ExternalAccess *e2e.ExternalAccessParam // `mapstructure:"ExternalAccess"`
}

func readTestConfigFile() (certConfig TestConfigEntry, err error) {
	va := viper.New()
	va.AddConfigPath(".")
	va.SetConfigType("yaml")
	va.SetConfigName("testConfig")
	// print the config file with path that viper object is going to read
	err = va.ReadInConfig() // Find and read the config file
	if err != nil {         // Handle errors reading the config file
		return certConfig, fmt.Errorf("can't find config file: %w ", err)
	}

	err = va.Unmarshal(&certConfig)
	if err != nil {
		return certConfig, fmt.Errorf("unable to decode Config: %s ", err)
	}
	return certConfig, nil
}

func main() {
	// minSize := "8Gi"
	fmt.Println("New main")
	testConfig, err := readTestConfigFile()
	if err != nil {
		log.Fatalf("unable to read test config file, %s", err.Error())
	}
	if testConfig.TestConfig.ExternalAccess != nil {
		err = e2e.ExternalAccessSuite(testConfig.TestConfig.ExternalAccess)
		if err != nil {
			fmt.Println(err)
		}
		// @TO-DO improve the logic for cleanup
		e2e.CleanNameSpace(e2e.GetNameSpace())
	}
}
