package main

import (
	"code.google.com/p/go-charset/charset"
	_ "code.google.com/p/go-charset/data"
	"encoding/xml"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

type WirelessData struct {
	XMLName  xml.Name  `xml:"detection-run"`
	Version  string    `xml:"kismet-version,attr"`
	Networks []Network `xml:"wireless-network"`
}

type Network struct {
	ESSID   SSID     `xml:"SSID"`
	BSSID   string   `xml:"BSSID"`
	Channel int      `xml:"channel"`
	Clients []Client `xml:"wireless-client"`
	Power   int      `xml:"snr-info>max_signal_dbm"`
}

type SSID struct {
	Ftime   string   `xml:"first-time,attr"`
	Ltime   string   `xml:"last-time,attr"`
	Packets int      `xml:"packets"`
	Encrypt []string `xml:"encryption"`
	ESSID   string   `xml:"essid"`
	Speed   float32  `xml:"max-rate"`
}

type Client struct {
	Number  int      `xml:"number,attr"`
	Ftime   string   `xml:"first-time,attr"`
	Ltime   string   `xml:"last-time,attr"`
	MAC     string   `xml:"client-mac"`
	Probes  []string `xml:"SSID>ssid"`
	Packets int      `xml:"packets>total"`
	Power   int      `xml:"snr-info>max_signal_dbm"`
}

func kismoExtract(fileName string) (WirelessData, error) {
	var k WirelessData
	r, err := os.Open(fileName)
	if err != nil {
		return k, err
	}
	defer r.Close()

	// Convert Kismet XML Charset to UTF-8
	d := xml.NewDecoder(r)
	d.CharsetReader = charset.NewReader
	err = d.Decode(&k)
	if err != nil {
		return k, err
	}

	return k, nil
}

func ParseArg(list interface{}) map[string]bool {
	result := make(map[string]bool)

	if list == nil {
		return result
	}
	opt := list.(string)
	if content, err := ioutil.ReadFile(opt); err == nil {
		for _, val := range strings.Split(string(content), "\n") {
			result[val] = true
		}
	} else if match, err := regexp.MatchString(":", opt); match && err == nil {
		for _, val := range strings.Split(opt, ",") {
			if val != "" {
				val = strings.ToUpper(val)
				result[val] = true
			}
		}
	} else {
		for _, val := range strings.Split(opt, ",") {
			if val != "" {
				result[val] = true
			}
		}
	}

	return result
}
