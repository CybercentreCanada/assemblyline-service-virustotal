"""Client to interact with VirusTotal API and cache."""

import base64
import time
from typing import Any, Dict, List

from assemblyline_v4_service.common.request import ServiceRequest
from vt import APIError, Client

from virustotal.cache.client import CacheClient
from virustotal.cache.elasticsearch.client import ElasticClient

REPORT_API_MAP = {"file": "/files/{}", "url": "/urls/{}", "ip": "/ip_addresses/{}", "domain": "/domains/{}"}

MAX_RETRIES = 3


class VTClient:
    """Client to interact with VirusTotal API and cache."""

    def __init__(self, vt_client_kwargs: Dict[str, Any], cache_settings: List[Dict]):
        """Initialize the VirusTotal client."""
        # Only use cached data (ideal for air-gapped systems that can't reach out to VirusTotal)
        self.cache_only = cache_settings.get("cache_only", False)

        # Initialize VirusTotal client
        if not self.cache_only:
            self.vt = Client(**vt_client_kwargs)

        # Initialize clients to interact with a cache of VirusTotal data
        self.cache: List[CacheClient] = []
        for settings in cache_settings.get("backends", []):
            if settings["type"] == "elasticsearch":
                # Initialize a client that interacts with Elasticsearch
                self.cache.append(ElasticClient(**settings["params"]))

    def bulk_search(
        self, collection: Dict[str, List[str]], request: ServiceRequest, submit_allowed: bool = False
    ) -> Dict[str, List[Dict]]:
        """Perform a bulk search of all the different types of reports.

        Returns:
            A map of the feed type to a list of reports.

        """
        results = {"file": [], "url": [], "ip": [], "domain": []}

        # Iterate over all the cache clients to find information mentioned in the collection
        for cache in self.cache:
            r = cache.bulk_search(collection)
            for feed, reports in r.items():
                for report in reports:
                    # Remove reports from the collection that we've found results for
                    if report["id"] in collection[feed]:
                        collection[feed].remove(report["id"])

                # Merge results with the final output
                results[feed].extend(reports)

        # If we're only leveraging the cache, then return what we know
        if self.cache_only:
            return results

        # Otherwise seek out VirusTotal to provide information that isn't in the cache
        for feed, data in collection.items():
            retry_attempts = 0
            for d in data:
                while retry_attempts < MAX_RETRIES:
                    id = d
                    if feed == "url":
                        # Reference: https://docs.virustotal.com/reference/url
                        id = base64.urlsafe_b64encode(d.encode()).decode().strip("=")
                    resp = None
                    try:
                        resp = self.vt.get_json(REPORT_API_MAP[feed].format(id))["data"]
                    except APIError as e:
                        # Ref: https://docs.virustotal.com/reference/errors
                        if e.code == "NotFoundError":
                            # Sample not known to VT, proceed with submitting to VT if allowed
                            if submit_allowed:
                                # VirusTotal only support submitting files and URLs for scanning
                                try:
                                    if feed == "file":
                                        resp = self.vt.scan_file(
                                            request.file_contents, wait_for_completion=True
                                        ).to_dict()
                                    elif feed == "url":
                                        resp = self.vt.scan_url(d, wait_for_completion=True).to_dict()
                                except APIError as submit_error:
                                    if submit_error.code == "AlreadyExistsError":
                                        # Sample already exists in VT, proceed with fetching the report
                                        continue
                                    elif submit_error.code == "InvalidArgumentError":
                                        # Invalid data provided, skip to the next one
                                        break
                            else:
                                break
                        elif e.code in ["QuotaExceededError", "NotAvailableYet"]:
                            # VirusTotal API quota exceeded or hasn't finished processing, retry after 60 seconds
                            retry_attempts += 1
                            time.sleep(60)
                            continue
                        elif e.code == "InvalidArgumentError":
                            # Invalid ID provided, skip to the next one
                            break
                        else:
                            # Raise Exception for unknown handling to be fixed later
                            raise e

                    if resp:
                        collection[feed].remove(resp["id"] if resp["type"] != "url" else resp["attributes"]["url"])
                        results.setdefault(feed, []).append(resp)
                        break

        return results
