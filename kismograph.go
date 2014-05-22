package main

import (
	"fmt"
	"github.com/docopt/docopt.go"
	"log"
	"strings"
	"time"
)

type Dump struct {
	NetHeader    []string
	ClientHeader []string
	Networks     []string
	Clients      []string
}

// Fill header values for Wireless AP and Wireless client
func (d *Dump) Header() {
	d.NetHeader = []string{
		"BSSID",
		"First time seen",
		"Last time seen",
		"channel",
		"Speed",
		"Privacy",
		"Cipher",
		"Authentication",
		"Power",
		"# beacons",
		"# IV",
		"LAN IP",
		"ID-length",
		"ESSID",
		"Key"}
	d.ClientHeader = []string{
		"Station MAC",
		"First time seen",
		"Last time seen",
		"Power",
		"# packets",
		"BSSID",
		"Probed ESSIDs"}
}

// Split Kismet encryption settings into multiple values
func SplitEnc(e string) []string {
	crypt := strings.Split(e, "+")
	if len(crypt) > 1 {
		crypt = append(crypt[:1], strings.Split(crypt[1], "-")...)
	} else {
		return []string{"None", "", ""}
	}
	if len(crypt) > 2 {
		return crypt
	}
	return append(crypt, "")
}

// Convert Kismet date time value
func TimeConv(t string) string {
	time, err := time.Parse("Mon Jan _2 15:04:05 2006", t)
	if err != nil {
		log.Fatal(err.Error())
	}
	const layout = "2006-01-02 15:04:05"
	return time.Format(layout)
}

func (n Network) Dump(enc string) []string {
	nets := []string{}

	nets = append(nets, n.BSSID)
	nets = append(nets, TimeConv(n.ESSID.Ftime))
	nets = append(nets, TimeConv(n.ESSID.Ltime))
	nets = append(nets, fmt.Sprintf("%v", n.Channel))
	nets = append(nets, fmt.Sprintf("%v", n.ESSID.Speed))
	nets = append(nets, strings.Join(SplitEnc(enc), ", "))
	nets = append(nets, fmt.Sprintf("%v", n.Power))
	nets = append(nets, fmt.Sprintf("%v", n.ESSID.Packets))
	nets = append(nets, "")
	nets = append(nets, "")
	nets = append(nets, "")
	nets = append(nets, n.ESSID.ESSID)
	nets = append(nets, "")

	return nets
}

func (n Network) Check(enc string, bssid map[string]bool, essid map[string]bool, neg bool) []string {
	if n.BSSID == "00:00:00:00:00:00" {
		return nil
	}
	// If map[string] empty return nil
	// If map[string] match and neg false return value
	// If map[string] not match and neg true return value
	// Default return nil

	if len(bssid) == 0 && len(essid) == 0 {
		return n.Dump(enc)
	}
	if (bssid[n.BSSID] || essid[n.ESSID.ESSID]) && !neg {
		return n.Dump(enc)
	} else if !(bssid[n.BSSID] || essid[n.ESSID.ESSID]) && neg {
		return n.Dump(enc)
	}
	return nil
}

func (c Client) Dump(bssid string) []string {
	assoc := []string{}

	assoc = append(assoc, c.MAC)
	assoc = append(assoc, TimeConv(c.Ftime))
	assoc = append(assoc, TimeConv(c.Ltime))
	assoc = append(assoc, fmt.Sprintf("%v", c.Power))
	assoc = append(assoc, fmt.Sprintf("%v", c.Packets))
	if bssid == "00:00:00:00:00:00" {
		assoc = append(assoc, "(not associated)")
	} else {
		assoc = append(assoc, bssid)
	}
	assoc = append(assoc, strings.Join(c.Probes, ","))

	return assoc
}

func (c Client) Check(bssid string, b map[string]bool, p map[string]bool, neg bool) []string {
	if c.MAC == "00:00:00:00:00:00" {
		return nil
	}

	// If map[string] empty return nil
	// If map[string] match and neg false return value
	// If map[string] not match and neg true return value
	// Default return nil

	if len(b) == 0 && len(p) == 0 {
		return c.Dump(bssid)
	}
	for _, probe := range c.Probes {
		if p[probe] && !neg {
			return c.Dump(bssid)
		} else if !p[probe] && neg {
			return c.Dump(bssid)
		}
		return nil
	}
	if b[bssid] && !neg {
		return c.Dump(bssid)
	} else if !b[bssid] && neg {
		return c.Dump(bssid)
	}
	return nil
}

func (w WirelessData) Dump(delm string, bssid map[string]bool, essid map[string]bool, probe map[string]bool, neg bool) {
	d := Dump{}
	d.Header()

	for _, nets := range w.Networks {
		for _, enc := range nets.ESSID.Encrypt {
			data := nets.Check(enc, bssid, essid, neg)
			if data != nil {
				d.Networks = append(d.Networks, strings.Join(data, delm))
			}
		}
		for _, c := range nets.Clients {
			data := c.Check(nets.BSSID, bssid, probe, neg)
			if data != nil {
				d.Clients = append(d.Clients, strings.Join(data, delm))
			}
		}
	}

	fmt.Println(strings.Join(d.NetHeader, delm))
	for _, nets := range d.Networks {
		fmt.Println(nets)
	}
	fmt.Printf("\n\n%v\n", strings.Join(d.ClientHeader, delm))
	for _, c := range d.Clients {
		fmt.Println(c)
	}
}

func main() {
	arguments, err := docopt.Parse(usage, nil, true, "kismograph 1.0.0", false)
	if err != nil {
		log.Fatal("Error parsing usage. Error: ", err.Error())
	}

	b := ParseArg(arguments["--bssid"])
	e := ParseArg(arguments["--essid"])
	p := ParseArg(arguments["--probe"])

	neg := arguments["--negate"].(bool)
	f := arguments["<file>"].(string)
	data, err := kismoExtract(f)
	if err != nil {
		log.Fatal(err.Error())
	}

	data.Dump(", ", b, e, p, neg)

}
