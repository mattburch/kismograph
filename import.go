package main

import (
	"code.google.com/p/go-charset/charset"
	_ "code.google.com/p/go-charset/data"
	"encoding/xml"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

type WirelessData struct {
	XMLName  xml.Name  `xml:"detection-run"`
	Version  string    `xml:"kismet-version,attr"`
	Networks []Network `xml:"wireless-network"`
}

type Network struct {
	Type    string   `xml:"type,attr"`
	ESSID   []SSID   `xml:"SSID"`
	BSSID   string   `xml:"BSSID"`
	Channel int      `xml:"channel"`
	Clients []Client `xml:"wireless-client"`
	Power   int      `xml:"snr-info>max_signal_dbm"`
}

type SSID struct {
	Type    string   `xml:"type"`
	Ftime   string   `xml:"first-time,attr"`
	Ltime   string   `xml:"last-time,attr"`
	Packets int      `xml:"packets"`
	Encrypt []string `xml:"encryption"`
	ESSID   string   `xml:"essid"`
	Speed   float32  `xml:"max-rate"`
}

type Client struct {
	Type    string   `xml:"type,attr"`
	Number  int      `xml:"number,attr"`
	Ftime   string   `xml:"first-time,attr"`
	Ltime   string   `xml:"last-time,attr"`
	MAC     string   `xml:"client-mac"`
	Probes  []string `xml:"SSID>ssid"`
	Packets int      `xml:"packets>total"`
	Power   int      `xml:"snr-info>max_signal_dbm"`
}

type PSSID struct {
	Time    []string
	Packets int
	Encrypt []string
	ESSID   string
	Speed   float32
}

func (c *Client) TimeConv() []string {
	const layout = "2006-01-02 15:04:05"
	ftime, err := time.Parse("Mon Jan _2 15:04:05 2006", c.Ftime)
	if err != nil {
		log.Fatal(err.Error())
	}

	ltime, err := time.Parse("Mon Jan _2 15:04:05 2006", c.Ltime)
	if err != nil {
		log.Fatal(err.Error())
	}
	return []string{ftime.Format(layout), ltime.Format(layout)}
}

func (s *SSID) TimeConv() []string {
	const layout = "2006-01-02 15:04:05"
	ftime, err := time.Parse("Mon Jan _2 15:04:05 2006", s.Ftime)
	if err != nil {
		log.Fatal(err.Error())
	}

	ltime, err := time.Parse("Mon Jan _2 15:04:05 2006", s.Ltime)
	if err != nil {
		log.Fatal(err.Error())
	}
	return []string{ftime.Format(layout), ltime.Format(layout)}
}

func (s *SSID) SplitEnc(delm string) []string {
	var crypt []string

	for _, enc := range s.Encrypt {
		if enc == "None" || enc == "WEP" {
			crypt = append(crypt, strings.Join([]string{enc, "", ""}, delm))
			continue
		}
		t := strings.Split(enc, "+")
		t = append(t[:1], strings.Split(t[1], "-")...)
		if len(t) > 2 {
			crypt = append(crypt, strings.Join(t, delm))
		} else if len(t) > 1 {
			t = append(t, "")
			crypt = append(crypt, strings.Join(t, delm))
		} else {
			crypt = append(crypt, strings.Join([]string{"None", "", ""}, delm))
		}
	}

	return crypt
}

func (p *PSSID) FTimeComp(t string) bool {
	bt, err := time.Parse("2006-01-02 15:04:05", p.Time[0])
	if err != nil {
		log.Fatal(err.Error())
	}
	ct, err := time.Parse("2006-01-02 15:04:05", t)
	if err != nil {
		log.Fatal(err.Error())
	}

	if ct.Unix() < bt.Unix() {
		return true
	} else {
		return false
	}
}

func (p *PSSID) LTimeComp(t string) bool {
	bt, err := time.Parse("2006-01-02 15:04:05", p.Time[1])
	if err != nil {
		log.Fatal(err.Error())
	}
	ct, err := time.Parse("2006-01-02 15:04:05", t)
	if err != nil {
		log.Fatal(err.Error())
	}

	if ct.Unix() > bt.Unix() {
		return true
	} else {
		return false
	}
}

func (s *SSID) Compare(p PSSID, delm string) PSSID {
	if p.Time == nil {
		p.Time = s.TimeConv()
		p.Packets = s.Packets
		p.Encrypt = s.SplitEnc(delm)
		p.ESSID = s.ESSID
		p.Speed = s.Speed
	} else {
		t := s.TimeConv()
		if p.FTimeComp(t[0]) {
			p.Time[0] = t[0]
		}
		if p.LTimeComp(t[1]) {
			p.Time[1] = t[1]
		}
		if p.Packets < s.Packets {
			p.Packets = s.Packets
		}
		if strings.Join(p.Encrypt, "") != strings.Join(s.SplitEnc(delm), "") {
			p.Encrypt = s.SplitEnc(delm)
		}
		if p.ESSID == "" && s.ESSID != "" {
			p.ESSID = s.ESSID
		}
	}

	return p
}

func (n *Network) ParseSSID(delm string) PSSID {
	var pssid PSSID

	for _, s := range n.ESSID {
		if s.Type == "Beacon" {
			pssid = s.Compare(pssid, delm)
		} else if s.Type == "Probe Response" {
			pssid = s.Compare(pssid, delm)
		} else if s.Type == "Cached SSID" {
			continue
		}
	}

	return pssid
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
