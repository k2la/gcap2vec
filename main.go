package main

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

type Network struct {
	Devices []Device `yaml:"network"`
}

type Device struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
}

func main() {

	buf, err := ioutil.ReadFile("network.yaml")
	if err != nil {
		panic(err)
	}
	var network Network
	err = yaml.Unmarshal(buf, &network)
	if err != nil {
		panic(err)
	}

	// ファイル名取得
	pcaps := listFilesWalk("train")
	// vector 取得
	pcap2csvByDevice(pcaps, network)

	// // CSV に書き込み
	// writeCsv("train.csv", vector)
}
