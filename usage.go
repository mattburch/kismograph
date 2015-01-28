package main

const usage = `

Usage:
  kismograph [--bssid=<bssid> --essid=<essid> --probes=<probes>] [--nets | --clients] [--netsignal=<sig>] [--clientsignal=<sig> | --negate] <file>
  kismograph [--ad-hoc] [--nets | --clients] [--netsignal=<sig> | --clientsignal=<sig>] [--negate] <file>
  kismograph [--infra] [--nets | --clients] [--netsignal=<sig> | --clientsignal=<sig>] [--negate] <file>
  kismograph [--probing --probes=<probes>] [--nets | --clients] [--netsignal=<sig> | --clientsignal=<sig>] [--negate] <file>
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
`
