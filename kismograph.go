package main

import (
	"fmt"
	"github.com/docopt/docopt.go"
	"log"
	"strings"
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

func SplitEnc(s []SSID, delm string) []string {
	var crypt []string

	for _, ssid := range s {
		for _, enc := range ssid.Encrypt {
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
	}

	return crypt
}

func (n Network) Dump(p PSSID, enc string) []string {
	nets := []string{}

	nets = append(nets, n.BSSID)
	nets = append(nets, p.Time...)
	nets = append(nets, fmt.Sprintf("%v", n.Channel))
	nets = append(nets, fmt.Sprintf("%v", p.Speed))
	nets = append(nets, enc)
	nets = append(nets, fmt.Sprintf("%v", n.Power))
	nets = append(nets, fmt.Sprintf("%v", p.Packets))
	nets = append(nets, "")
	nets = append(nets, "")
	nets = append(nets, "")
	nets = append(nets, p.ESSID)
	nets = append(nets, "")

	return nets
}

func (n *Network) Check(p PSSID, arg map[string]interface{}, enc string, bssid map[string]bool, essid map[string]bool) []string {
	if n.BSSID == "00:00:00:00:00:00" {
		return nil
	}
	if n.Type == "probe" {
		return nil
	}
	if arg["--probing"].(bool) && !arg["--negate"].(bool) {
		return nil
	}

	// If map[string] empty return nil
	// If map[string] match and neg false return value
	// If map[string] not match and neg true return value
	// Default return nil
	if len(bssid) == 0 && len(essid) == 0 {
		return n.Dump(p, enc)
	}
	if (bssid[n.BSSID] || essid[p.ESSID]) && !arg["--negate"].(bool) {
		return n.Dump(p, enc)
	} else if !(bssid[n.BSSID] || essid[p.ESSID]) && arg["--negate"].(bool) {
		return n.Dump(p, enc)
	}

	return nil
}

func (c *Client) Dump(bssid string) []string {
	assoc := []string{}

	assoc = append(assoc, c.MAC)
	assoc = append(assoc, c.TimeConv()...)
	assoc = append(assoc, fmt.Sprintf("%v", c.Power))
	assoc = append(assoc, fmt.Sprintf("%v", c.Packets))
	if bssid == "00:00:00:00:00:00" {
		assoc = append(assoc, "(not associated)")
	} else if c.Type == "tods" {
		assoc = append(assoc, "(probing client)")
	} else {
		assoc = append(assoc, bssid)
	}
	assoc = append(assoc, strings.Join(c.Probes, ","))

	return assoc
}

func (c *Client) Check(bssid string, arg map[string]interface{}, b map[string]bool, p map[string]bool) []string {
	if c.MAC == "00:00:00:00:00:00" {
		return nil
	}
	if c.MAC == bssid && c.Type != "tods" {
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
		if p[probe] && !arg["--negate"].(bool) {
			return c.Dump(bssid)
		} else if !p[probe] && arg["--negate"].(bool) {
			return c.Dump(bssid)
		}
		return nil
	}
	if b[bssid] && !arg["--negate"].(bool) {
		return c.Dump(bssid)
	} else if !b[bssid] && arg["--negate"].(bool) {
		return c.Dump(bssid)
	}
	return nil
}

func (w *WirelessData) Dump(delm string, arg map[string]interface{}, bssid map[string]bool, essid map[string]bool, probe map[string]bool) {
	d := Dump{}
	d.Header()

	for _, net := range w.Networks {
		if arg["--ad-hoc"].(bool) && !arg["--negate"].(bool) && net.Type != "ad-hoc" {
			continue
		} else if arg["--ad-hoc"].(bool) && arg["--negate"].(bool) && net.Type == "ad-hoc" {
			continue
		}
		if arg["--infra"].(bool) && !arg["--negate"].(bool) && net.Type != "infrastructure" {
			continue
		} else if arg["--infra"].(bool) && arg["--negate"].(bool) && net.Type == "infrastructure" {
			continue
		}

		pssid := net.ParseSSID(delm)
		for _, enc := range pssid.Encrypt {
			data := net.Check(pssid, arg, enc, bssid, essid)
			if data != nil {
				d.Networks = append(d.Networks, strings.Join(data, delm))
			}
		}

		for _, c := range net.Clients {
			if arg["--probing"].(bool) && !arg["--negate"].(bool) && len(c.Probes) == 0 {
				continue
			} else if arg["--probing"].(bool) && !arg["--negate"].(bool) && c.Type != "tods" {
				continue
			} else if arg["--probing"].(bool) && arg["--negate"].(bool) && c.Type == "tods" {
				continue
			}
			if (arg["--ad-hoc"].(bool) || arg["--infra"].(bool)) && !arg["--negate"].(bool) && c.Type == "tods" {
				continue
			}

			data := c.Check(net.BSSID, arg, bssid, probe)
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
	arguments, err := docopt.Parse(usage, nil, true, "kismograph 1.1.0", false)
	if err != nil {
		log.Fatal("Error parsing usage. Error: ", err.Error())
	}

	b := ParseArg(arguments["--bssid"])
	e := ParseArg(arguments["--essid"])
	p := ParseArg(arguments["--probe"])

	f := arguments["<file>"].(string)
	data, err := kismoExtract(f)
	if err != nil {
		log.Fatal(err.Error())
	}

	data.Dump(", ", arguments, b, e, p)

}
