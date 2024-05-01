# The Boys Digital Signature over a network traffic conversation

### Cmd tool for generating digital signature using the pcap analyser 

> ```python pcap_analyser.py /home/kali/boys/digitalsign/pcapanalyser/samples/ summarise```
> 
| Protocol | Number of Packets | First timestamp | Last timestamp | Avg packet length |
|----------|-------------------|-----------------|----------------|-------------------|
| TCP | 78725 | 20:52:22.484 | 18:57:20.768 | 666.58 |
| UDP | 872 | 20:52:39.603 | 18:57:20.989 | 150.41 |
| ARP | 12 | 20:53:52.941 | 18:57:10.955 | 51.0 |
| ICMP | 80 | 20:54:19.161 | 18:56:50.385 | 149.35 |


# Help and commands
Commands:
-  Summarize: Generate a summary of the PCAP file, including packet types/protocols, average length, and the first and last timestamps.
-    URL's: Present all HTTP URIs detected in the PCAP file.
-    Filenames: Show filenames embedded in the URIs extracted from the URIs command output.
-    Emails: Exhibit all SMTP emails found in the PCAP file.
-    Conversations: Display the number of packets sent in conversations between two hosts.
-    Plength - Packet length provide the average packet length for each detected protocol.
-    Timestamps: Present the first and last timestamps for each detected protocol.
-    Graph: Show a graph plotting the number of packets over time.
-    KML: Generate a KML graph with source and destination locations for each packet.
-    All - Execute all of the above commands

# Output Location
- By default all outputs are saved to pcapanalyser/outputs
- Open the Google Earth
- From the local directory import the kml file for the geoip location
# Third party packages
- See requirements.txt
- ```pip install -r requirements.txt```

