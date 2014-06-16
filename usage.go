package main

const usage = `

Usage:
  kismograph [--bssid=<bssid> --essid=<essid> --probes=<probes>] [--negate] <file>
  kismograph [--ad-hoc] [--negate] <file>
  kismograph [--infra] [--negate] <file>
  kismograph [--probing --probe=<probes>] [--negate] <file>
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
  --ad-hoc                Filter on Ad-Hoc networks and clients
  --infra                 Filter on Infrastructure networks and clients
  --probing               Filter on Probing clients
`
