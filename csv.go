package main

import (
	"encoding/csv"
	"os"
)

func write_csv(filename string, dataset [][]string) {
	output, err := os.Create(filename)
	if err != nil {
	}
	defer output.Close()
	writer := csv.NewWriter(output)
	for _, data := range dataset {
		writer.Write(data)
		writer.Flush()
	}
}
