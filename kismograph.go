package main

import (
	"fmt"
	"github.com/docopt/docopt.go"
	"log"
	"strconv"
	"strings"
)

type Dump struct {
	NetHeader    []string
	ClientHeader []string
	Networks     []string
	Clients      []string
}

type Filter struct {
	BSSID        map[string]bool
	ESSID        map[string]bool
	Probes       map[string]bool
	NetSignal    int
	ClientSignal int
	Probing      bool
	AdHoc        bool
	Infra        bool
	Nets         bool
	Clients      bool
	Negate       bool
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

func (n *Network) Dump(p PSSID, enc string) []string {
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

func (n *Network) Check(p PSSID, filter Filter, enc string) []string {
	if n.BSSID == "00:00:00:00:00:00" {
		return nil
	}
	if n.Type == "probe" {
		return nil
	}
	if filter.Probing && !filter.Negate {
		return nil
	}

	if len(filter.BSSID) == 0 && len(filter.ESSID) == 0 {
		return n.Dump(p, enc)
	}
	if (filter.BSSID[n.BSSID] || filter.ESSID[p.ESSID]) && !filter.Negate {
		return n.Dump(p, enc)
	} else if !(filter.BSSID[n.BSSID] || filter.ESSID[p.ESSID]) && filter.Negate {
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

func (c *Client) Check(bssid string, filter Filter) []string {
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

	if len(filter.BSSID) == 0 && len(filter.Probes) == 0 {
		return c.Dump(bssid)
	}
	for _, probe := range c.Probes {
		if filter.Probes[probe] && !filter.Negate {
			return c.Dump(bssid)
		} else if !filter.Probes[probe] && filter.Negate {
			return c.Dump(bssid)
		}
		return nil
	}
	if filter.BSSID[bssid] && !filter.Negate {
		return c.Dump(bssid)
	} else if !filter.BSSID[bssid] && filter.Negate {
		return c.Dump(bssid)
	}
	return nil
}

func (w *WirelessData) Dump(delm string, filter Filter) {
	d := Dump{}
	d.Header()

	for _, net := range w.Networks {

		if filter.Nets || (!filter.Nets && !filter.Clients) {
			if filter.AdHoc && !filter.Negate && net.Type != "ad-hoc" {
				continue
			} else if filter.AdHoc && filter.Negate && net.Type == "ad-hoc" {
				continue
			}
			if filter.Infra && !filter.Negate && net.Type != "infrastructure" {
				continue
			} else if filter.Infra && filter.Negate && net.Type == "infrastructure" {
				continue
			}
			if filter.NetSignal != 0 && net.Power < filter.NetSignal {
				continue
			}

			pssid := net.ParseSSID(delm)
			for _, enc := range pssid.Encrypt {
				data := net.Check(pssid, filter, enc)
				if data != nil {
					d.Networks = append(d.Networks, strings.Join(data, delm))
				}
			}
		}

		if filter.Clients || (!filter.Nets && !filter.Clients) {
			for _, c := range net.Clients {
				if filter.Probing && !filter.Negate && len(c.Probes) == 0 {
					continue
				} else if filter.Probing && !filter.Negate && c.Type != "tods" {
					continue
				} else if filter.Probing && filter.Negate && c.Type == "tods" {
					continue
				}
				if (filter.AdHoc || filter.Infra) && !filter.Negate && c.Type == "tods" {
					continue
				}
				if filter.ClientSignal != 0 && c.Power < filter.ClientSignal {
					continue
				}

				data := c.Check(net.BSSID, filter)
				if data != nil {
					d.Clients = append(d.Clients, strings.Join(data, delm))
				}
			}
		}
	}

	if filter.Nets || (!filter.Nets && !filter.Clients) {
		fmt.Println(strings.Join(d.NetHeader, delm))
		for _, nets := range d.Networks {
			fmt.Println(nets)
		}
		fmt.Println()
	}

	if filter.Clients || (!filter.Nets && !filter.Clients) {
		fmt.Println(strings.Join(d.ClientHeader, delm))
		for _, c := range d.Clients {
			fmt.Println(c)
		}
		fmt.Println()
	}

}

func main() {
	arguments, err := docopt.Parse(usage, nil, true, "kismograph 1.3", false)
	if err != nil {
		log.Fatal("Error parsing usage. Error: ", err.Error())
	}
	var filter Filter
	filter.Nets = arguments["--nets"].(bool)
	filter.Clients = arguments["--clients"].(bool)
	filter.BSSID = ParseArg(arguments["--bssid"])
	filter.ESSID = ParseArg(arguments["--essid"])
	filter.Probes = ParseArg(arguments["--probes"])
	filter.AdHoc = arguments["--ad-hoc"].(bool)
	filter.Negate = arguments["--negate"].(bool)
	filter.Infra = arguments["--infra"].(bool)

	if arguments["--netsignal"] != nil {
		sig, err := strconv.Atoi(arguments["--netsignal"].(string))
		if err != nil {
			log.Fatal(err.Error())
		}

		if sig > 0 {
			filter.NetSignal = sig - (sig * 2)
		} else {
			filter.NetSignal = sig
		}
	}
	if arguments["--clientsignal"] != nil {
		sig, err := strconv.Atoi(arguments["--clientsignal"].(string))
		if err != nil {
			log.Fatal(err.Error())
		}

		if sig > 0 {
			filter.ClientSignal = sig - (sig * 2)
		} else {
			filter.ClientSignal = sig
		}
	}

	f := arguments["<file>"].(string)
	data, err := kismoExtract(f)
	if err != nil {
		log.Fatal(err.Error())
	}

	data.Dump(", ", filter)

}
