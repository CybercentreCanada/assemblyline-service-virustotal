# VirusTotal Service

This Assemblyline This service checks (and optionally submits) files/URLs to VirusTotal for analysis.

**NOTE**: This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

## Execution

This service will actually submit the file to VirusTotal for analysis over the v3 REST API.

Because the file leaves the Assemblyline infrastructure, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave our system.

## Configuration
----
### Service Configuration
|Name|Description|
|:---:|:---|
|api_key|Global VirusTotal API key for the system to use if the submitter doesn't provide their own|
|host|VirusTotal host defaults to external `https://www.virustotal.com` but can be specified for testing or internal hosting.|
|proxy|Proxy to connect to VirusTotal with|
|av_config|Configuration block that tells the service to ignore/remap certain AV verdicts from the File Report. See [Service Manifest](./service_manifest.yml) for more details.|

### Submission Parameters
|Name|Description|
|:---:|:---|
|api_key|Individual VirusTotal API key|
|dynamic_submit|Instructs the service to submit to VirusTotal if there is no existing report about the submission|
|relationships|A list of comma-separated relationships that we want to get about the submission|
|analyze_relationship|Perform analysis on the relationships to the submission|
|download_evtx|Have the service download EVTX from sandbox analyses.|
|download_pcap|Have the service download EVTX from sandbox analyses.|

Note: For operations like `download_evtx` & `download_pcap`, the `analyze_relationship` flag is required as it entails more API calls to
retrieve additional reports to get a full picture of the analysis done by VirusTotal.
