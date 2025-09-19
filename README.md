<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Plasma Framework</h2>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
![Powered By: EDF](https://img.shields.io/badge/Powered_By-CERT_EDF-FFFF33.svg?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-2596be.svg?style=for-the-badge)](LICENSE)

</div>

<br>

# Introduction

Plasma framework and command line tool to dissect and extract structured information from forensics artifacts.

It can be easily extended by adding new dissectors. Most dissectors are based on other FOSS projects such as:

- [LIEF](https://github.com/lief-project/LIEF) for executables processing
- [Scapy](https://github.com/secdev/scapy) for packet captures processing
- [libyal](https://github.com/libyal) for Windows artifacts processing
- [construct](https://github.com/construct/construct) for raw structures processing
- [volatility3](https://github.com/volatilityfoundation/volatility3) for memory dump processing (SOON)
- [MVT](https://github.com/mvt-project/mvt) extracted files for normalization

Many thanks to these projects for their contribution to the cybersecurity open source community!

<br>

## Getting Started

Plasma releases are available on Github and Pypi. Use Python 3.12+ and a virtual environment for best experience.

```bash
# Setup plasma to use as a library
python3 -m pip install edf-plasma-dissectors
# Setup plasma to use as a command line tool
python3 -m pip install edf-plasma-cli
# Display integrated help
plasma -h
plasma dissect -h
# List available plasma dissectors
plasma list
# Dissect artifacts in source/ with plasma filtering dissectors by tags
plasma dissect --filter 'tags:linux,pcap' source/ output/
```

<br>

## License

Distributed under the [MIT License](LICENSE).

<br>

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

### Past contributors (before open sourcing)

- [koromodako](https://github.com/koromodako)
- [SPToast](https://github.com/SPToast)
- [alex532h](https://github.com/alex532h)

<br>

## Security

To report a (suspected) security issue, see [SECURITY.md](SECURITY.md).
