"""Client to interact with VirusTotal API and cache."""

import base64
from typing import Any, Dict, List

from vt import APIError, Client

from virustotal.cache.client import CacheClient
from virustotal.cache.elasticsearch.client import ElasticClient

REPORT_API_MAP = {"file": "/files/{}", "url": "/urls/{}", "ip": "/ip_addresses/{}", "domain": "/domains/{}"}


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

    def bulk_search(self, collection: Dict[str, List[str]], submit_allowed: bool = False) -> Dict[str, List[Dict]]:
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
        if not submit_allowed:
            return results

        # Otherwise seek out VirusTotal to provide information that isn't in the cache
        for feed, data in collection.items():
            for d in data:
                if feed == "url":
                    # Reference: https://docs.virustotal.com/reference/url
                    d = base64.urlsafe_b64encode(d.encode()).decode().strip("=")
                try:
                    resp = self.vt.get_json(REPORT_API_MAP[feed].format(d))["data"]
                    results.setdefault(feed, []).append(resp)
                    collection[feed].remove(resp["id"])
                except APIError as e:
                    if e.code == "NotFoundError":
                        # Sample not known to VT, proceed with submitting to VT if allowed
                        pass
                    else:
                        # Raise Exception for unknown handling to be fixed later
                        raise e

        return results
