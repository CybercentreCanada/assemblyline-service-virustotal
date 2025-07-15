"""Assemblyline service for VirusTotal."""

import re
from urllib.parse import urlparse

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection

import virustotal.reports.behaviour as behaviour_analysis
import virustotal.reports.file as file_analysis
import virustotal.reports.ip_domain as ip_domain_analysis
import virustotal.reports.url as url_analysis
from virustotal.client import VTClient
from virustotal.reports.common.processing import AVResultsProcessor

TAG_TO_MODULE = {
    "ip": ip_domain_analysis,
    "domain": ip_domain_analysis,
    "uri": url_analysis,
    "behaviour": behaviour_analysis,
}


class VirusTotal(ServiceBase):
    """Assemblyline service for VirusTotal."""

    def __init__(self, config=None):
        """Initialize the VirusTotal service."""
        super(VirusTotal, self).__init__(config)
        self.client = None
        self.safelist_interface = self.get_api_interface().get_safelist
        self.allow_dynamic_resubmit = self.config.get("allow_dynamic_resubmit", False)

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
            self.config["av_config"]["hit_threshold"],
        )

        # Instantiate safelist(s)
        try:
            safelist = self.safelist_interface(
                [
                    "network.static.uri",
                    "network.dynamic.uri",
                    "network.static.domain",
                    "network.dynamic.domain",
                    "network.static.ip",
                    "network.dynamic.ip",
                ]
            )
            regex_list = []
            self.safelist_match = []

            # Extend with safelisted matches
            [self.safelist_match.extend(match_list) for _, match_list in safelist.get("match", {}).items()]

            # Extend with safelisted regex
            [regex_list.extend(regex_) for _, regex_ in safelist.get("regex", {}).items()]

            self.safelist_regex = re.compile("|".join(regex_list))

        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service server: {e}. Continuing without it..")

    def start(self):
        """Start the VirusTotal service."""
        self.log.debug("VirusTotal service started")

    def get_results(self, report_list, tag, title_insert, host_uri_map={}) -> ResultSection:
        """Create a ResultSection for the given report list.

        Returns:
            ResultSection: A ResultSection containing the VirusTotal results

        """
        module = TAG_TO_MODULE[tag]
        parent_section = ResultSection(f"Extracted {title_insert} by Assemblyline")
        section_titles = list()
        for report in report_list:
            section = module.v3(report, self.processor)
            if section and section.title_text not in section_titles:
                section_titles.append(section.title_text)
                if tag in ["ip", "domain"]:
                    for host, uris in host_uri_map.items():
                        # Check to see if URI is a related to the IP/Domain either directly or as a subdomain
                        if host and (host == section.title_text or host.endswith(f".{section.title_text}")):
                            [section.add_tag("network.static.uri", uri) for uri in uris]
                parent_section.add_subsection(section)
                module.attach_ontology(self.ontology, report)

        if tag in ["ip", "domain", "uri"]:
            # Reorganize sections so that scoring sections are first and non-scoring are last and collapsed
            sorted_sections = []
            for section in parent_section.subsections:
                if not section.heuristic:
                    # Auto collapse sections where a heuristic wasn't raised
                    section.auto_collapse = True
                    sorted_sections.append(section)
                else:
                    # Add scored section to the beginning of the list
                    sorted_sections.insert(0, section)
            # Sort sections by score
            sorted_sections = sorted(
                sorted_sections, key=lambda x: x.heuristic.score if x.heuristic else 0, reverse=True
            )

            parent_section._subsections = sorted_sections

        return parent_section

    def execute(self, request: ServiceRequest):
        """Execute the VirusTotal service."""
        # Initialize VirusTotal client along with cache clients, if configured
        self.client = VTClient(
            vt_client_kwargs={
                "apikey": request.get_param("api_key") or self.config.get("api_key"),
                "proxy": self.config.get("proxy") or None,
                "host": self.config.get("host") or None,
            },
            cache_settings=self.config.get("cache", {}),
        )

        # Maintain a record of items that you want to query
        query_collection = {"file": [], "url": [], "ip": [], "domain": []}

        if request.file_type.startswith("uri/"):
            # URI files only
            query_collection["url"].append(request.task.fileinfo.uri_info.uri)
            if re.match(IP_ONLY_REGEX, request.task.fileinfo.uri_info.hostname):
                query_collection["ip"].append(request.task.fileinfo.uri_info.hostname)
            else:
                query_collection["domain"].append(request.task.fileinfo.uri_info.hostname)
        else:
            # Otherwise looks for files based on the SHA256
            query_collection["file"] = [request.sha256]

        result = Result()
        dynamic_submit = request.get_param("dynamic_submit") and self.allow_dynamic_resubmit

        if request.get_param("exhaustive_search"):
            # Search for all tags associated to the file task and add it to the query collection
            for k, v in request.task.tags.items():
                if "uri" in k and v not in query_collection["url"]:
                    query_collection["url"].extend(v)
                elif "domain" in k and v not in query_collection["domain"]:
                    query_collection["domain"].extend(v)
                elif "ip" in k and v not in query_collection["ip"]:
                    query_collection["ip"].extend(v)

            # Remove duplicates
            for ioc in ["url", "ip", "domain"]:
                query_collection[ioc] = list(set(query_collection[ioc]))

            # Pre-filter network IOCs based on AL safelist
            if self.safelist_regex or self.safelist_match:

                def filter_items(x_list: list):
                    regex_matches = list(filter(self.safelist_regex.match, x_list))
                    # Remove on regex and exact matches
                    [x_list.remove(match_item) for match_item in regex_matches]
                    [x_list.remove(x) for x in x_list if any(match_item in x for match_item in self.safelist_match)]

                for ioc in ["url", "ip", "domain"]:
                    filter_items(query_collection[ioc])

        [self.log.info(f"{k} queries: {len(v)}") for k, v in query_collection.items()]

        # Execute a bulk search for VirusTotal data
        result_collection = self.client.bulk_search(query_collection, request, submit_allowed=dynamic_submit)

        [self.log.info(f"{k} results: {len(v)}") for k, v in result_collection.items()]

        # Create ResultSections
        for file_report in result_collection["file"]:
            try:
                file_result = file_analysis.v3(file_report, request.file_name, self.processor)
                if request.get_param("exhaustive_search"):
                    # Extract relational IOCs from the file report and perform a lookup
                    for relationship, data in file_report.get("relationships", {}).items():
                        if not data.get("data", []):
                            # Skip if no data to create a subsection from
                            continue

                        relationship_type = None
                        if "url" in relationship:
                            relationship_type = "url"
                        elif "ip" in relationship:
                            relationship_type = "ip"
                        elif "domain" in relationship:
                            relationship_type = "domain"

                        # Create a subsection for each relationship type
                        if relationship_type:
                            relationship_section = ResultSection(relationship.replace("_", " ").title())
                            for report in self.client.bulk_search(
                                {relationship_type: [d["id"] for d in data["data"]]},
                                request,
                                submit_allowed=dynamic_submit,
                            )[relationship_type]:
                                tag = "uri" if relationship_type == "url" else relationship_type
                                relationship_section.add_subsection(
                                    TAG_TO_MODULE[tag].v3(
                                        # Score the report IFF it isn't pertaining to an ITW relationship
                                        # ITW relationships can lead users to believe the IOCs are embedded in the file
                                        report,
                                        self.processor,
                                        score_report=not relationship.startswith("itw_"),
                                    )
                                )
                            if relationship_section.subsections:
                                file_result.add_subsection(relationship_section)

                result.add_section(file_result)
                file_analysis.attach_ontology(self.ontology, file_report)
            except Exception as e:
                self.log.error(f"Problem producing {file_report['id']} file report: {e}")

        # Create a map of the domains/IPs and the URIs they're associated to for tagging purposes
        host_uri_map = dict()
        for uri in query_collection["url"]:
            host_uri_map.setdefault(urlparse(uri).hostname, []).append(uri)

        [
            result.add_section(section)
            for section in [
                self.get_results(result_collection["url"], "uri", "URLs"),
                self.get_results(result_collection["ip"], "ip", "IPs", host_uri_map),
                self.get_results(result_collection["domain"], "domain", "Domains", host_uri_map),
            ]
            if section.subsections
        ]

        request.result = result

    def get_tool_version(self) -> str:
        """Return the version of the VirusTotal results.

        Returns:
            str: The version of the VirusTotal service based on configuration

        """
        if not (self.client and self.client.cache):
            # If no caching is configured, then return default tool version
            return super().get_tool_version()
        else:
            # Otherwise, return the version based on the cache client
            return self.client.get_cache_version()
