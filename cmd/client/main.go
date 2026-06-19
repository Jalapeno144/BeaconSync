package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Heartbeat struct {
	Hostname string `json:"hostname"`
	Status   string `json:"status"`
}

func main() {
	hb := Heartbeat{
		Hostname: "client-01",
		Status:   "alive",
	}

	data, err := json.Marshal(hb)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(
		"http://127.0.0.1:8080/heartbeat", // test server ip
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)
}
