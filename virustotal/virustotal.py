import os
import time
from base64 import b64encode
from copy import deepcopy

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from vt import APIError, Client

from virustotal.reports.behaviour import attach_ontology as append_sandbox_ontology
from virustotal.reports.behaviour import v3 as parse_sandbox_report
from virustotal.reports.common.processing import AVResultsProcessor
from virustotal.reports.file import attach_ontology as append_file_ontology
from virustotal.reports.file import v3 as parse_file_report
from virustotal.reports.ip_domain import v3 as parse_network_report
from virustotal.reports.url import v3 as parse_url_report

MAX_RETRY = 3


def get_tag_values(section: ResultSection):
    values = []
    for v in section.tags.values():
        values.extend(v)

    for s in section.subsections:
        values.extend(get_tag_values(s))

    return values


class VirusTotal(ServiceBase):
    def __init__(self, config=None):
        super(VirusTotal, self).__init__(config)
        self.client = None
        self.safelist_interface = self.get_api_interface().get_safelist
        self.allow_dynamic_resubmit = self.config.get("allow_dynamic_resubmit")

        sig_safelist = []
        [
            sig_safelist.extend(match_list)
            for _, match_list in self.safelist_interface(["av.virus_name"]).get("match", {}).items()
        ]
        self.processor = AVResultsProcessor(
            self.config["av_config"]["term_blocklist"],
            self.config["av_config"]["revised_sig_score_map"],
            self.config["av_config"]["revised_kw_score_map"],
            sig_safelist,
            self.config["av_config"]["specific_AVs"],
        )

    def start(self):
        self.log.debug("VirusTotal service started")

    def execute(self, request: ServiceRequest):
        # Ensure we can actually create a client connection
        try:
            # Submitter's API key should be used first, global is a fallback if configured
            self.client = Client(
                apikey=request.get_param("api_key") or self.config.get("api_key"),
                proxy=self.config.get("proxy") or None,
                host=self.config.get("host") or None,
            )
        except ValueError as e:
            self.log.error("No API key found for VirusTotal")
            raise e

        result = Result()
        scan_url = bool(request.task.metadata.get("submitted_url", None) and request.task.depth == 0)
        dynamic_submit = request.get_param("dynamic_submit") and self.allow_dynamic_resubmit
        response = None
        if scan_url and not request.get_param("ignore_submitted_url"):
            submitted_url = request.task.metadata["submitted_url"]
            response = self.common_scan(
                type="url",
                sample=submitted_url,
                id=b64encode(submitted_url.encode()).decode(),
                dynamic_submit=dynamic_submit,
            )
        else:
            relationships = request.get_param("relationships")
            if (
                request.get_param("download_evtx") or request.get_param("download_pcap")
            ) and "behaviours" not in relationships:
                # Requesting to download Sandbox files but relationship wasn't specified in request
                relationships += ",behaviours"

            response = self.common_scan(
                type="file",
                sample=open(request.file_path, "rb"),
                # ID with relationship params
                id=f"{request.sha256}?relationships={relationships}",
                dynamic_submit=dynamic_submit,
            )

        result_section = self.analyze_response(response, request)

        if result_section:
            # Add tagging for dynamic IOCs into URL report sections
            if request.get_param("analyze_relationship"):
                for section in result_section.subsections:
                    if section.title_text == "Related Objects":
                        behavior_section = [
                            relation_section
                            for relation_section in section.subsections
                            if relation_section.title_text == "Behaviours"
                        ]
                        if not behavior_section:
                            break
                        dynamic_iocs = get_tag_values(behavior_section[0])
                        for relation_section in section.subsections:
                            if relation_section.title_text == "Behaviours":
                                continue

                            for subsection in relation_section.subsections:
                                tags = deepcopy(subsection.tags)
                                for k, v in tags.items():
                                    [
                                        subsection.add_tag(k.replace("static", "dynamic"), ioc)
                                        for ioc in v
                                        if ioc in dynamic_iocs
                                    ]

            result.add_section(result_section)

        request.result = result

    def analyze_response(self, response: dict, request: ServiceRequest):
        if not response:
            return
        elif response.get("error", {}).get("code") == "NotFoundError":
            return

        def download_sandbox_files():
            sandbox_name = response["attributes"]["sandbox_name"]
            id = response["id"]
            for downloadable_file in ["evtx", "pcap"]:
                if request.get_param(f"download_{downloadable_file}") and response["attributes"].get(
                    f"has_{downloadable_file}"
                ):
                    self.log.info(f"Downloading {downloadable_file} from {sandbox_name}")
                    # Download file and append for other services to analyze
                    fn = f"{id}_{downloadable_file}"
                    dest_path = os.path.join(self.working_directory, fn)
                    with open(dest_path, "wb") as fh:
                        fh.write(self.client.get(f"/file_behaviours/{id}/{downloadable_file}").read())
                    request.add_extracted(dest_path, fn, description=f"{downloadable_file.upper()} from {sandbox_name}")

        report_type = response["type"]
        result_section = None
        if report_type == "file":
            result_section = parse_file_report(response, request.file_name, self.processor)
            append_file_ontology(self.ontology, response)

            # Get as much information as we can about other related objects (entails more API requests)
            relationships_section = ResultSection("Related Objects", parent=result_section, auto_collapse=True)
            if request.get_param("analyze_relationship"):
                # Only concerned with relationships that contain content (minimize API calls needed)
                for relationship in [k for k, v in response.get("relationships", {}).items() if v.get("data")]:
                    # Create a pretty title text for the section
                    title_text = (
                        relationship.title()
                        .replace("_", " ")
                        .replace("Ip", "IP")
                        .replace("Url", "URL")
                        .replace("Itw", "ITW")
                    )
                    interim_section = ResultSection(title_text=title_text, parent=relationships_section)
                    for analysis in self.client.get_json(f"/files/{request.sha256}/{relationship}?limit=40")["data"]:
                        subsection = self.analyze_response(analysis, request)
                        if subsection:
                            interim_section.add_subsection(subsection)
            else:
                # Create a section that tags known relationships but don't assess them for scoring purposes
                for relationship, data in response.get("relationships", {}).items():
                    data = data["data"]
                    if not data:
                        continue
                    # Create a pretty title text for the section
                    title_text = (
                        relationship.title()
                        .replace("_", " ")
                        .replace("Ip", "IP")
                        .replace("Url", "URL")
                        .replace("Itw", "ITW")
                    )
                    body = [d["id"] for d in data]
                    tag_type = data[0]["type"] if data[0]["type"] != "ip_address" else "ip"
                    tags = {}
                    if tag_type != "file_behaviour":
                        tags[f"network.static.{tag_type}"] = body
                    else:
                        # Place holder in case we want to fetch sandbox files
                        continue

                    interim_section = ResultSection(
                        title_text=title_text,
                        body=", ".join(body),
                        body_format=BODY_FORMAT.TEXT,
                        parent=relationships_section,
                        tags=tags,
                        auto_collapse=True,
                    )

        elif report_type == "url":
            result_section = parse_url_report(response)
        elif report_type in ["domain", "ip_address"]:
            result_section = parse_network_report(response)
        elif report_type == "file_behaviour":
            result_section = parse_sandbox_report(response)
            append_sandbox_ontology(self.ontology, response)
            download_sandbox_files()

        return result_section

    def common_scan(self, type: str, sample, id, dynamic_submit):
        try:
            # Sample already submitted to VT, return existing report
            return self.client.get_json(f"/{type}s/{id}")["data"]
        except APIError as e:
            if e.code == "NotFoundError":
                # Sample not known to VT, proceed with submitting to VT if allowed
                pass
            else:
                # Raise Exception for unknown handling to be fixed later
                raise e

        def submit(retry_attempt: int = 0):
            # Submit sample to VT for analysis
            json_response = None
            if retry_attempt < MAX_RETRY:
                try:
                    if type == "file":
                        json_response = self.client.scan_file(sample, wait_for_completion=True).to_dict()
                    else:
                        json_response = self.client.scan_url(sample, wait_for_completion=True).to_dict()
                except APIError as e:
                    if "NotFoundError" in e.code:
                        self.log.warning(f"VirusTotal has nothing on this {type}.")
                    elif "QuotaExceededError" in e.code:
                        self.log.warning("Quota Exceeded. Trying again in 60s.")
                        time.sleep(60)
                        retry_attempt += 1
                        return submit(retry_attempt)
                    else:
                        self.log.error(e)
            return json_response

        # Only submit to VT if requested by the submitter
        if dynamic_submit:
            return submit()
