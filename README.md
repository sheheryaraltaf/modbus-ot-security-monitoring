# Modbus/TCP Traffic Analysis & Anomaly Detection

OT/ICS security exercise: baseline analysis of a real Modbus/TCP packet capture, packet-level
field inspection, and validation of detection logic by injecting a synthetic unauthorized
write and confirming it is caught by both Wireshark and a Suricata rule.

Full write-up with screenshots: [`report/OT_Protocol_Analysis_Report.docx`](report/OT_Protocol_Analysis_Report.docx)

## What was done

1. **Baseline analysis (Wireshark)** - identified the master (`141.81.0.10`) and 13 slave
   devices from TCP Conversations, confirmed roles using Modbus Query/Response labelling,
   and characterized the function code distribution (reads vs. writes).
2. **Write command baseline** - isolated 1,793 write commands (Function Codes 15 and 16)
   directed at slaves, all originating from the expected master.
3. **Packet-level field inspection** - opened individual write packets to record register/coil
   addresses and values, then scanned the full set for outliers. Addresses formed two
   consistent clusters (~0-400 and ~1,100-2,258); no anomaly found.
4. **Timing check** - inspected inter-packet timing for write commands; gaps were irregular
   (0.0003s-0.65s) with no burst pattern, consistent with normal asynchronous polling.
5. **Anomaly injection (Scapy)** - since the real capture was clean, a synthetic unauthorized
   write was injected (source IP changed to `192.168.50.99`) to test detection logic.
6. **Detection rule (Suricata)** - wrote and validated a rule that flags any Write Multiple
   Coils/Registers command not originating from the known master. Confirmed the rule fires
   on the injected packet (`fast.log` alert, `sid:1000003`).

## Key finding

Modbus has no built-in authentication, so any device that can reach port 502 can issue
commands a PLC will accept as valid. The real capture showed no anomaly, but detection logic
built purely from the observed baseline (known master IP + observed write function codes)
successfully caught a synthetic unauthorized write on the first try.

## Repo structure

```
.
├── report/
│   └── OT_Protocol_Analysis_Report.docx   # full write-up with screenshots
├── scripts/
│   └── inject_anomaly.py                  # Scapy script: injects unauthorized write
└── rules/
    └── modbus.rules                       # Suricata detection rule
```

## Tools used

- **Wireshark** - protocol analysis, filtering, packet-level inspection
- **Scapy** - synthetic packet crafting for anomaly injection
- **Suricata** - rule-based detection, validated against the injected capture

## Reproducing the detection test

```bash
pip install scapy
python scripts/inject_anomaly.py        # produces ModbusTCP_injected.pcap

suricata -r ModbusTCP_injected.pcap -S rules/modbus.rules -l ./logs
cat ./logs/fast.log                      # alert should appear here
```

## Limitations

- Analysis is based on a static capture, not live traffic.
- The anomaly was synthetically injected rather than naturally occurring in the dataset.
- The Suricata rule covers only the write types observed in this capture (Function Codes
  15 and 16); Function Codes 05 and 06 were not present and are not covered.
