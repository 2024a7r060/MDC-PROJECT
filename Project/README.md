# DNS Security Monitoring

A local defensive DNS monitor. It captures DNS packets visible on the machine's network interfaces, stores only observed queries, and assigns a deterministic, explainable risk score. The dashboard does not generate traffic or seed sample events.

The active implementation is consolidated in `app.py`: it contains the Streamlit dashboard, Scapy packet monitor, deterministic domain analysis, and SQLite repository. The `tests/` directory contains focused verification tests.

## Requirements

- Python 3.10 or newer
- Windows: install [Npcap](https://npcap.com/) with WinPcap-compatible API support. Start the terminal or VS Code with administrator privileges if packet capture permissions require elevation.
- DNS monitoring works only for DNS packets visible to the capture interface. DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), VPN/virtual interfaces, browser DNS caches, and external encrypted resolvers can hide queries from this sensor.

## Install and Run

From this project directory:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

The sensor starts when the dashboard starts. Its status and any capture error appear in the sidebar. If capture is unavailable, install Npcap, grant capture permissions, then choose **Retry capture**. No events are inserted unless an actual DNS query packet is captured.

The default capture interface follows the operating system's IPv4 default route. Set `DNS_CAPTURE_INTERFACE` to a Scapy/Npcap interface name or device path to override it.

## Verify Real Browsing Activity

1. Start the dashboard and confirm that capture is running.
2. Open a new private/incognito browser window or clear the browser/system DNS cache so an old cached answer is not reused.
3. Visit a hostname that your browser has not recently resolved, such as a site you have not opened in this session.
4. Within a refresh interval, check **DNS Activity** for the matching queried hostname, packet timestamp, DNS type, source and destination IPs, and any captured response.
5. Compare the event timestamp with a packet capture from Wireshark on the same interface using `dns.qry.name == "the-domain-you-visited"`.

Browsers often query several domains for one page. A page load can also produce no visible port-53 packet if the browser or operating system uses cached DNS or encrypted DNS.

## Detection and Risk Scoring

The score is deterministic and bounded from 0 to 100. Defaults are `0-29 SAFE`, `30-69 SUSPICIOUS`, and `70-100 HIGH RISK`. Change `DNS_RISK_SUSPICIOUS_THRESHOLD` and `DNS_RISK_HIGH_THRESHOLD` to configure thresholds; invalid combinations fall back to 30 and 70.

Signals include optional VirusTotal domain reputation, a weak configurable TLD watchlist, long/high-entropy subdomain labels, subdomain depth, numeric density, query frequency, and the number of distinct subdomains under a parent in a short window. A random-looking name by itself does not produce a high-risk classification. Each event stores the triggered reasons with its score. VirusTotal lookups require `DNS_VIRUSTOTAL_API_KEY`; without it, reputation is reported as unavailable and local heuristics continue to work. API failures never count as a clean reputation result.

When long/high-entropy labels coincide with repeated queries or many distinct subdomains, or query and unique-subdomain rates are both high, the event is labeled **Potential DNS Anomaly / Possible DNS Tunneling**. This is a heuristic, not proof of tunneling.

## Storage and Privacy

SQLite stores packet timestamp, queried name/type, source and destination IPs, matching response data when seen, score, reasons, and packet-capture provenance. Duplicate retransmissions with the same source, destination, query, type, and DNS transaction ID inside 750 ms are ignored. Response records are correlated to their query; unmatched responses are not listed as queries.

The first run upgrades the old database and removes its unprovenanced demonstration rows because they cannot be distinguished from genuine events. The **Data & Settings** page can clear captured queries and alerts at any time. New databases start empty.

## Limits

- This is a host-level packet sensor, not an inline DNS resolver or network-wide tap. It does not see other devices' traffic unless the host is configured as their DNS gateway or the interface receives mirrored traffic.
- Standard packet capture usually requires administrator/root privileges and a supported capture driver (Npcap on Windows, libpcap on Linux/macOS).
- DNS-over-HTTPS and DNS-over-TLS are encrypted and not decoded. QUIC-based encrypted DNS is also outside this sensor's scope.
- A capture failure is displayed; the application never substitutes simulated data.
- Heuristic scores prioritize investigation. They are not a verdict that a host is compromised.
