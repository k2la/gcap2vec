package main

import (
	"io/ioutil"
	"log"
	"path/filepath"
)

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
			files = append(files, fullPath)
		} else {
			files = append(files, listFilesWalk(fullPath)...)
		}
	}
	return files
}
