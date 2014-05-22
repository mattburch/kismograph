package main

const usage = `

Usage:
  kismograph <file> [--bssid=<bssid> --essid=<essid> --probe=<probes>] [--negate]
  kismograph -h | --help
  kismograph --version

Options:
  -h, --help              Show usage.
  --version               Show version.
  --bssid <bssid>         Line delimeted file or comma delimeted
                          BSSID values
  --essid <essid>         Line delimeted file or comma delimeted
                          ESSID values
  --probe <probe>       Line delimeted file or comma delimeted
                          values for client probe requests
  --negate                Negate provided bssid / essid values
`
