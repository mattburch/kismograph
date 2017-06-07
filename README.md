kismograph
==============

Utility for converting Kismet XML files into CSV files for airgraph-ng.

##Download
Binary packages for every supported operating system are availble [here](https://github.com/mattburch/kismograph/releases/latest).

##Usage
```
Usage:
  kismograph [--bssid=<bssid> --essid=<essid> --probes=<probes>] [--nets [--netsignal=<sig>] | --clients [--clientsignal=<sig>]] [--negate] [--delm <delm>] <file>
  kismograph [--ad-hoc] [--nets [--netsignal=<sig>] | --clients [--clientsignal=<sig>]] [--negate] [--delm <delm>] <file>
  kismograph [--infra] [--nets [--netsignal=<sig>] | --clients [--clientsignal=<sig>]] [--negate] [--delm <delm>] <file>
  kismograph [--probing --probes=<probes>] [--nets [--netsignal=<sig>] | --clients [--clientsignal=<sig>]] [--negate] [--delm <delm>] <file>
  kismograph -h | --help
  kismograph --version

Options:
  -h, --help              Show usage.
  --version               Show version.
  --bssid <bssid>         Line delimeted file or comma delimeted
                          BSSID values
  --essid <essid>         Line delimeted file or comma delimeted
                          ESSID values
  --probes <probe>        Line delimeted file or comma delimeted
                          values for client probe requests
  --negate                Negate provided bssid / essid values
  --nets                  Filter output for networks only
  --clients               Filter output for clients only
  --ad-hoc                Filter on Ad-Hoc networks and clients
  --infra                 Filter on Infrastructure networks and clients
  --netsignal <sig>       Set maximum signal strength for networks
  --clientsignal <sig>    Set maximum signal strength for clients
  --probing               Filter on Probing clients
  --delm <delm>           Output delimiter (default: ", ")
```
