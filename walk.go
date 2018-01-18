package main

import (
	"io/ioutil"
	"log"
	"path/filepath"
)

func isPcap(path string) bool {
	e := filepath.Ext(path)
	if e == ".pcap" {
		return true
	}
	return false
}

func listFilesWalk(searchPath string) []string {
	var files = []string{}
	searchPath, err := filepath.Abs(searchPath)
	if err != nil {
		log.Fatal(err)
	}
	fis, err := ioutil.ReadDir(searchPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, fi := range fis {
		fullPath := filepath.Join(searchPath, fi.Name())
		if !fi.IsDir() {
			if isPcap(fullPath) {
				files = append(files, fullPath)
			}
		} else {
			files = append(files, listFilesWalk(fullPath)...)
		}
	}
	return files
}
