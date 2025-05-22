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

![image](https://github.com/user-attachments/assets/ad22e63f-b130-4464-b8fd-98728152347d)

VirusTotal identifies the file as a Trojan and ransomware, with multiple references to Cerber, a known Ransomware-as-a-Service (RaaS) variant.

![image](https://github.com/user-attachments/assets/3762e57e-5611-4a33-aa1f-38c3ecc62ff7)

The executable download was initiated in frame 8558, following a request to the specified resource.

![image](https://github.com/user-attachments/assets/6dd4a3cf-a249-4dd6-bae6-a829f98cbcc9)

The affected system was identified as 10.3.14.134 (Knutson-PC), likely a Windows-based desktop or laptop.

![image](https://github.com/user-attachments/assets/c0416c25-6c73-456d-9019-bd57d61449e0)

![image](https://github.com/user-attachments/assets/6de4ca04-7837-404f-abc4-f3c1a72339d9)

Security alerts were triggered immediately upon the request to the .top domain, indicating that Knutson-PC was likely the initial point of infection.

![image](https://github.com/user-attachments/assets/e13b95ca-7112-4d5c-9326-524cd99fdb61)

The network traffic shows that 10.3.14.134 (Knutson-PC) established TLS sessions with Yahoo and Google servers, suggesting the user may have been accessing email and potentially clicked a malicious link that led to the initial compromise. Shortly thereafter, another executable file was downloaded by 10.3.14.131 (DESKTOP-K1BN9E2), indicating a possible secondary infection.

![image](https://github.com/user-attachments/assets/7051a9bf-1538-47a6-bcc9-f43183f6b91b)

![image](https://github.com/user-attachments/assets/bc4c9241-be4d-499c-a8b1-ade556f48b77)

The malicious file was downloaded from this site: http://kuzem2.kku.edu.tr/load.php. Further analysis revealed that the system was likely infected after visiting a legitimate website (holinergroup.com) that had been compromised to host or inject malicious JavaScript.

Analysis of the network traffic from the DESKTOP-K1BN9E2 system shows several encrypted requests to Google servers, consistent with user activity following a phishing email. This suggests that the infection may have occurred via a coordinated phishing campaign, similar to the initial compromise.

![image](https://github.com/user-attachments/assets/c5b0598a-3289-4d93-bcda-ca4d304c14aa)

![image](https://github.com/user-attachments/assets/888971af-9c45-45c2-b1b7-1d2485419f4c)

![image](https://github.com/user-attachments/assets/c73b9d64-3178-4521-bcaf-059301df7cd4)

Analysis of the network traffic from the DESKTOP-K1BN9E2 system shows several encrypted requests to Google servers, consistent with user activity following a phishing email. This suggests that the infection may have occurred via a coordinated phishing campaign, similar to the initial compromise.
This HTML file requested is flagged as a JavaScript Trojan Downloader. Also linked to Spora Ransomware.

![image](https://github.com/user-attachments/assets/e076489e-97dc-476d-8348-2a1dea57740e)

We can see that spora is also distributed over email, which would match our infection hypothesis.

![image](https://github.com/user-attachments/assets/0f387831-5f61-44d6-b6b7-832ab23898ea)

## Conclusion

### Date and time of the suspicious activity.
The initial suspicious activity occurred on February 11, 2017, at 03:02:41 AM, marked by the first DNS request to a .top domain, which hosted the executable responsible for the initial infection.

![image](https://github.com/user-attachments/assets/c01ff8e9-aa42-49d7-8f76-4266690c982a)

### IP address, MAC address, and host name of the computer that was involved.

![image](https://github.com/user-attachments/assets/cec6e862-5c94-49ce-bebb-df8218f66036)

- 10.3.14.131 (DESKTOP-K1BN9E2) MAC: 002564184C2A.

- 10.3.14.134 (Knutson-PC) MAC: 14DAE95B421C.

### A summary of what happened.

The systems identified as DESKTOP-K1BN9E2 and Knutson-PC were compromised as a result of a phishing campaign, likely delivered via Gmail, which directed users to malicious websites. These sites initiated the download of ransomware-as-a-service payloads that encrypted the users' data and issued ransom demands.

### A conclusion with recommendations for any follow-up actions, if required.

The ransomware infections on systems DESKTOP-K1BN9E2 and Knutson-PC were the result of successful phishing attacks that led to the download and execution of malicious payloads. These attacks highlight vulnerabilities in user awareness and email security controls.

- To prevent future incidents of this nature, the following actions are recommended:

- Conduct regular phishing awareness training to educate staff on recognizing and reporting suspicious emails.

- Implement advanced email filtering and threat detection systems to block malicious attachments and links before reaching end users.

- Deploy script-blocking browser extensions and endpoint protection tools to prevent the execution of malicious code from compromised websites.

- Maintain regular, offline system backups to ensure data recovery in the event of encryption or system compromise for critical data.

## References 

- "Ransom.Spora." Malwarebytes Labs, 21 Mar. 2017, www.malwarebytes.com/blog/detections/ransom-spora/
- "Ransom.Cerber." Malwarebytes Labs, 17 Nov. 2016, www.malwarebytes.com/blog/detections/ransom-cerber/


