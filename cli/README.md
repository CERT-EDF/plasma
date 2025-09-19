# EDF Plasma CLI

## Introduction

This package implements a command line interface to perform dissection of forensics
artifacts from the command line using Plasma Framework's dissectors.

<br>

## Setup

```bash
# first, install edf-plasma-dissectors dependencies
apt install autoconf \
            automake \
            autopoint \
            build-essential \
            git \
            libsystemd-dev \
            libtool \
            pkg-config \
            python3-dev \
            python3-venv
# create a virtual environment
python3 -m venv venv
# install edf-plasma-cli (will also install edf-plasma-core and edf-plasma-dissectors)
venv/bin/python -m pip install edf-plasma-cli
# start dissecting artifacts using dissect command
venv/bin/plasma -h
```

<br>

## Usage

> [!TIP]
> - Use `-f` to switch from `rich` output to `json` output to allow piping into `jq` for automation purpose
> - Use `-p` to load custom plugins from a directory

<br>

### List available dissectors

```bash
venv/bin/plasma list
```
```
[2025-09-17T09:52:49] INFO     (plasma.cli): Plasma v1.0.0
╭────────────────────────────┬───────────────────────┬─────────────────────────────────────────────────╮
│ android_mvt_appops         │ android,mvt           │ Dissect MVT Android appops output               │
│ android_mvt_files          │ android,mvt           │ Dissect MVT Android files output                │
│ android_mvt_packages       │ android,mvt           │ Dissect MVT Android packages output             │
│ android_mvt_packages_perms │ android,mvt           │ Dissect MVT Android packages permissions output │
│ android_mvt_processes      │ android,mvt           │ Dissect MVT Android processes output            │
│ android_mvt_sms            │ android,mvt           │ Dissect MVT Android sms output                  │
│ elf_ctor_dtor              │ elf,linux             │ Dissect ELF constructors and destructors        │
│ elf_export                 │ elf,linux             │ Dissect ELF binary exported symbols             │
│ elf_import                 │ elf,linux             │ Dissect ELF binary imported symbols             │
│ elf_info                   │ elf,linux             │ Dissect ELF information                         │
│ elf_library                │ elf,linux             │ Dissect ELF binary needed libraries             │
│ elf_section                │ elf,linux             │ Dissect ELF binary sections                     │
│ elf_segment                │ elf,linux             │ Dissect ELF binary segments                     │
│ generic_chromium_history   │ generic,linux,windows │ Dissect Chromium download and visit history     │
│ generic_firefox_history    │ generic,linux,windows │ Dissect Firefox download and visit history      │
│ generic_ssh_pub_key        │ generic,linux,windows │ Dissect SSH public key                          │
│ ios_mvt_analytics_ad_daily │ ios,mvt               │ Dissect MVT iOS os analytics ad daily output    │
│ ios_mvt_apps               │ ios,mvt               │ Dissect MVT iOS apps output                     │
│ ios_mvt_datausage          │ ios,mvt               │ Dissect MVT iOS datausage output                │
│ ios_mvt_manifest           │ ios,mvt               │ Dissect MVT iOS manifest output                 │
│ ios_mvt_safari_history     │ ios,mvt               │ Dissect MVT iOS safari history output           │
│ ios_mvt_safari_state       │ ios,mvt               │ Dissect MVT iOS safari state output             │
│ ios_mvt_shortcuts          │ ios,mvt               │ Dissect MVT iOS shortcuts output                │
│ ios_mvt_sms                │ ios,mvt               │ Dissect MVT iOS sms output                      │
│ ios_mvt_tcc                │ ios,mvt               │ Dissect MVT iOS tcc output                      │
│ ios_mvt_webkit_rsrc_load   │ ios,mvt               │ Dissect MVT iOS webkit resource load output     │
│ ios_mvt_whatsapp           │ ios,mvt               │ Dissect MVT iOS whatsapp output                 │
│ ios_sysdiag_bluetooth      │ ios,sysdiag           │ Dissect iOS sysdiagnose bluetooth status output │
│ ios_sysdiag_disk           │ ios,sysdiag           │ Dissect iOS sysdiagnose disk output             │
│ ios_sysdiag_mount          │ ios,sysdiag           │ Dissect iOS sysdiagnose mount output            │
│ ios_sysdiag_ps             │ ios,sysdiag           │ Dissect iOS sysdiagnose ps output               │
│ ios_sysdiag_remotectl      │ ios,sysdiag           │ Dissect iOS sysdiagnose remotectl output        │
│ ios_sysdiag_shutdown       │ ios,sysdiag           │ Dissect iOS sysdiagnose shutdown output         │
│ ios_sysdiag_wifi           │ ios,sysdiag           │ Dissect iOS sysdiagnose disk output             │
│ linux_apt_history          │ linux                 │ Dissect apt history log                         │
│ linux_apt_sources          │ linux                 │ Dissect apt sources                             │
│ linux_at_acl               │ linux                 │ Dissect at.allow and at.deny                    │
│ linux_at_jobs              │ linux                 │ Dissect atjobs                                  │
│ linux_auditd               │ linux                 │ Dissect auditd log                              │
│ linux_authlog              │ linux                 │ Dissect auth.log* and secure* journals          │
│ linux_crontab              │ linux                 │ Dissect crontabs                                │
│ linux_dpkg                 │ linux                 │ Dissect dpkg                                    │
│ linux_fslist               │ linux                 │ Dissect file list                               │
│ linux_fstab                │ linux                 │ Dissect fstab                                   │
│ linux_group                │ linux                 │ Dissect group                                   │
│ linux_history              │ linux                 │ Dissect *_history files                         │
│ linux_hosts                │ linux                 │ Dissect hosts                                   │
│ linux_journal_auth         │ linux                 │ Dissect auth events from systemd journal        │
│ linux_journal_cron         │ linux                 │ Dissect cron events from systemd journal        │
│ linux_journal_ftp          │ linux                 │ Dissect ftp events from systemd journal         │
│ linux_logrotate            │ linux                 │ Dissect logrotate                               │
│ linux_netstat              │ linux                 │ Network connections                             │
│ linux_passwd               │ linux                 │ Dissect passwd                                  │
│ linux_resolv               │ linux                 │ Dissect resolv                                  │
│ linux_shadow               │ linux                 │ Dissect shadow                                  │
│ linux_systemd_service      │ linux                 │ Dissect systemd service                         │
│ linux_systemd_timer        │ linux                 │ Dissect systemd timer                           │
│ linux_udev_rules           │ linux                 │ Dissect udev rules                              │
│ linux_usbguard_device      │ linux                 │ Dissect device events from usbguard log         │
│ linux_usbguard_policy      │ linux                 │ Dissect policy events from usbguard log         │
│ linux_wtmp_utmp            │ linux                 │ Dissect utmp, wtmp and btmp binary logs         │
│ linux_xdg_autostart        │ linux                 │ Dissect xdg autostart                           │
│ linux_yum_history          │ linux                 │ Dissect yum history log                         │
│ linux_yum_sources          │ linux                 │ Dissect yum sources                             │
│ pcap_dns_answers           │ pcap                  │ Dissect DNS answers from PCAP                   │
│ pcap_dns_queries           │ pcap                  │ Dissect DNS queries from PCAP                   │
│ pcap_http_requests         │ pcap                  │ Dissect DNS http requests from PCAP             │
│ pcap_proto_stats           │ pcap                  │ Dissect protocols from PCAP                     │
│ pcap_tcp_conv              │ pcap                  │ Dissect TCP conversations from PCAP             │
│ pcap_tls_cert              │ pcap                  │ Dissect TLS certificates from PCAP              │
│ pcap_tls_client_hello      │ pcap                  │ Dissect TLS client hello from PCAP              │
│ pcap_tls_server_hello      │ pcap                  │ Dissect TLS server hello from PCAP              │
│ pcap_udp_conv              │ pcap                  │ Dissect UDP conversations from PCAP             │
│ pe_ctor_dtor               │ pe,windows            │ Dissect PE constructors and destructors         │
│ pe_export                  │ pe,windows            │ Dissect PE exported symbols                     │
│ pe_import                  │ pe,windows            │ Dissect PE imported symbols                     │
│ pe_info                    │ pe,windows            │ Dissect PE information                          │
│ pe_resource                │ pe,windows            │ Dissect PE resources                            │
│ pe_rich                    │ pe,windows            │ Dissect PE rich header                          │
│ pe_section                 │ pe,windows            │ Dissect PE sections                             │
│ pe_signature               │ pe,windows            │ Dissect PE signatures                           │
│ windows_appx               │ windows               │ Dissect AppX manifest files                     │
│ windows_evtx               │ windows               │ Dissect events from EVTX files                  │
│ windows_iis                │ windows               │ Dissect IIS journal entries                     │
│ windows_lnk                │ windows               │ Dissect LNK                                     │
│ windows_jumplist           │ windows               │ Dissect jumplist entries                        │
│ windows_mft                │ windows               │ Dissect entries from NTFS MFT                   │
│ windows_mssql              │ windows               │ Dissect MSSQL ERRORLOG entries                  │
│ windows_netstat            │ windows               │ Network connections                             │
│ windows_powershell         │ windows               │ Dissect powershell command line history         │
│ windows_prefetch           │ windows               │ Dissect prefetch                                │
│ windows_registry           │ windows               │ Dissect registry hives                          │
│ windows_srudb              │ windows               │ Dissect SRUDB.dat                               │
│ windows_task               │ windows               │ Dissect scheduled tasks                         │
│ windows_usnj               │ windows               │ Dissect NTFS USN journal                        │
│ windows_webcache           │ windows               │ Dissect WebCacheV01.dat                         │
│ windows_wmi                │ windows               │ WMI event filter/consumer bindings              │
│ windows_zone_identifier    │ windows               │ Dissect Zone.Identifier ADS                     │
╰────────────────────────────┴───────────────────────┴─────────────────────────────────────────────────╯
```

<br>

### List available dissectors

> [!TIP]
> Use `--fiter` to select dissectors by `tags` or by `slug`

```bash
plasma dissect --filter 'slug:linux_authlog,linux_wtmp_utmp' /tmp/demo/target /tmp/demo/output
```
```
[2025-09-17T10:06:13] INFO     (plasma.cli): Plasma v1.0.0
                      INFO     (plasma.dissectors.abc): file selected: linux_authlog (filepath=/tmp/demo/target/auth.log.4.gz)
                      INFO     (plasma.dissectors.abc): file selected: linux_authlog (filepath=/tmp/demo/target/auth.log.3.gz)
                      INFO     (plasma.dissectors.abc): file selected: linux_authlog (filepath=/tmp/demo/target/auth.log)
                      INFO     (plasma.dissectors.abc): file selected: linux_authlog (filepath=/tmp/demo/target/auth.log.2.gz)
                      INFO     (plasma.dissectors.abc): file selected: linux_authlog (filepath=/tmp/demo/target/auth.log.1)
                      INFO     (plasma.dissectors.abc): dissect many start: linux_authlog (files=5)
                      INFO     (plasma.dissectors.abc): dissection start: linux_authlog (filepath=/tmp/demo/target/auth.log.4.gz)
                      INFO     (plasma.dissectors.abc): dissection complete: linux_authlog (records=2307, errors=0, time=0:00:00.012953)
                      INFO     (plasma.dissectors.abc): dissection start: linux_authlog (filepath=/tmp/demo/target/auth.log.3.gz)
[2025-09-17T10:06:14] INFO     (plasma.dissectors.abc): dissection complete: linux_authlog (records=2151, errors=0, time=0:00:00.012987)
                      INFO     (plasma.dissectors.abc): dissection start: linux_authlog (filepath=/tmp/demo/target/auth.log)
                      INFO     (plasma.dissectors.abc): dissection complete: linux_authlog (records=785, errors=0, time=0:00:00.004493)
                      INFO     (plasma.dissectors.abc): dissection start: linux_authlog (filepath=/tmp/demo/target/auth.log.2.gz)
                      INFO     (plasma.dissectors.abc): dissection complete: linux_authlog (records=1726, errors=0, time=0:00:00.010326)
                      INFO     (plasma.dissectors.abc): dissection start: linux_authlog (filepath=/tmp/demo/target/auth.log.1)
                      INFO     (plasma.dissectors.abc): dissection complete: linux_authlog (records=4580, errors=0, time=0:00:00.024124)
                      INFO     (plasma.dissectors.abc): dissection many complete: linux_authlog (files=5, errors=0, time=0:00:00.069889)
                      INFO     (plasma.dissectors.abc): file selected: linux_wtmp_utmp (filepath=/tmp/demo/target/wtmp)
                      INFO     (plasma.dissectors.abc): dissect many start: linux_wtmp_utmp (files=1)
                      INFO     (plasma.dissectors.abc): dissection start: linux_wtmp_utmp (filepath=/tmp/demo/target/wtmp)
                      INFO     (plasma.dissectors.abc): dissection complete: linux_wtmp_utmp (records=1842, errors=0, time=0:00:00.106052)
                      INFO     (plasma.dissectors.abc): dissection many complete: linux_wtmp_utmp (files=1, errors=0, time=0:00:00.107151)
╭─────────────────┬─────────────────────────────────────────┬───────────────────────────────────────────────╮
│ linux_authlog   │ /tmp/demo/output/linux_authlog.csv.gz   │ /tmp/demo/output/linux_authlog_error.csv.gz   │
│ linux_wtmp_utmp │ /tmp/demo/output/linux_wtmp_utmp.csv.gz │ /tmp/demo/output/linux_wtmp_utmp_error.csv.gz │
╰─────────────────┴─────────────────────────────────────────┴───────────────────────────────────────────────╯
```

<br>

## License

Distributed under the [MIT License](LICENSE).

<br>

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/CERT-EDF/plasma/blob/main/CONTRIBUTING.md).

## Past contributors (before open sourcing)

- [koromodako](https://github.com/koromodako)
- [SPToast](https://github.com/SPToast)
- [alex532h](https://github.com/alex532h)

<br>

## Security

To report a (suspected) security issue, see [SECURITY.md](https://github.com/CERT-EDF/plasma/blob/main/SECURITY.md).
