package main

import ()

func main() {
	// ファイル名取得
	pcaps := listFilesWalk("train")
	// vector 取得
	vector := pcap2vec(pcaps)
	// CSV に書き込み
	writeCsv("train.csv", vector)
}
