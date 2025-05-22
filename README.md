#  Ransomware Scenario Investigation

## Objective  
To investigate a suspected ransomware infection using network forensics tools by analyzing a packet capture (PCAP) file, identifying malicious activity, and providing actionable recommendations based on the findings.

##  Skills Learned  
- Recovered deleted files and extracted evidence using Autopsy and OSForensics  
- Analyzed file systems to reconstruct user activity  
- Examined metadata and user artifacts to link evidence to the suspect  
- Investigated cloud storage sync data to identify stored and shared files  
- Correlated documents, images, and communications to build a full case narrative  
- Applied Windows file system knowledge to track user behavior  
- Created clear forensic reports to communicate findings effectively  
- Analyzed packet captures to identify suspicious file downloads and threat vectors  
- Used VirusTotal to confirm malware signatures and identify ransomware strains  
- Tracked phishing campaign behavior using network forensic tools

##  Tools Used

<div>
  
  <img src="https://img.shields.io/badge/-Wireshark-1E90FF?style=for-the-badge&logo=Wireshark&logoColor=white" />
  <img src="https://img.shields.io/badge/-VirusTotal-3949AB?style=for-the-badge&logo=virustotal&logoColor=white" />
  <img src="https://img.shields.io/badge/-Network%20Miner-800080?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/-PacketTotal-0078D7?style=for-the-badge&logoColor=white" />
  
</div>

- **Wireshark**: An advanced network protocol analyzer used to inspect network traffic and identify anomalies or threats.  
- **VirusTotal**: An online service that aggregates antivirus scans and metadata to analyze suspicious files and URLs.  
- **NetworkMiner**: A passive network sniffer and packet content analyzer that extracts files and metadata from PCAP files.  
- **PacketTotal**: An automated online PCAP analysis tool that provides detailed insights into network traffic, protocols, and potential threats by scanning and visualizing packet captures.

  ##  Scenario Description
  
After receiving recognition for outstanding performance in the Security Operations Center (SOC) during a recent assignment, the analyst’s previous employer—an organization focused on novelty Valentine’s Day merchandise—unexpectedly declared bankruptcy due to an unsustainable post-holiday business model.

Now employed at a new organization themed around "March Madness," the analyst has taken on a more solitary role within a lean cybersecurity team. While the organization’s business model may raise concerns, the position provides a valuable opportunity to maintain and sharpen network defense skills while awaiting responses from more promising and stable job prospects.

In this role, the analyst is responsible for monitoring network traffic and investigating suspicious activity. Although security resources are limited, they have occasional access to full packet captures from targeted IP addresses. One such capture, vday.pcap, has been flagged for review. The analyst has been tasked with examining the packet capture and producing a comprehensive investigation report.

The report must include:

- The date and time of the suspicious activity

- The IP address, MAC address, and host name of the affected system

- A summary of the observed incident

- A conclusion with actionable recommendations for follow-up or mitigation

  ##   Results
  
  While reviewing the transferred files, I identified a downloaded executable (.exe) file. Windows Defender immediately flagged this file as ransomware.

![image](https://github.com/user-attachments/assets/c12852de-739e-41e1-ad57-66c5d73fe8b5)
![image](https://github.com/user-attachments/assets/a2cbb660-cacd-48f5-bbb1-64958b4d1721)
VirusTotal relates to a Trojan, Ransomware, and many mentions of Cerber (a Ransomware-as-a-Service malware type).









