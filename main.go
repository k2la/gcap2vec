package main

import (
	"fmt"
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
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
	var n Network
	err = yaml.Unmarshal(buf, &n)
	if err != nil {
		panic(err)
	}
	fmt.Println(n.Devices[0].IP)

	// // ファイル名取得
	// pcaps := listFilesWalk("train")
	// // vector 取得
	// vector := pcap2vec(pcaps)
	// // CSV に書き込み
	// writeCsv("train.csv", vector)
}
