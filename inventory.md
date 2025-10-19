# VM / Container Inventory

| Node Name        | Role                     | OS Version       | IP Address    | Notes                    |
|-----------------|--------------------------|----------------|---------------|--------------------------|
| sip-server       | SIP Server               | Ubuntu 22.04   | 192.168.56.10 | Main call handling       |
| siem             | SIEM / Log Collector     | Ubuntu 22.04   | 192.168.56.11 | Log analysis             |
| packet-capture   | Packet Capture Node      | Kali Linux     | 192.168.56.12 | Captures SIP/RTP traffic |
| client1          | Test Client              | Ubuntu 22.04   | 192.168.56.20 | Test call generator      |
| client2          | Test Client              | Ubuntu 22.04   | 192.168.56.21 | Test call generator      |
