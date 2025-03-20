"""Client to interact with Elasticsearch for cached VirusTotal reports."""

import re
from hashlib import sha256
from typing import Dict, List, Optional

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.base import SHA256_REGEX
from elasticsearch import Elasticsearch

from virustotal.cache.client import CacheClient

HASH_MATCHER = re.compile(SHA256_REGEX)


class ElasticClient(CacheClient):
    """Cache client that interacts with Elasticsearch."""

    def __init__(self, hosts: List[str], index_aliases: Dict[str, List[str]], apikey: str = None):
        """Intitialize client to interact with Elasticsearch."""
        self.client = Elasticsearch(
            hosts=hosts, api_key=apikey, verify_certs=False, max_retries=5, retry_on_timeout=True
        )
        self.index_aliases = index_aliases
        self.indices = {}
        self.total_docs = 0

        # Initialize starting values for client
        self.check_cache()

    def bulk_search(self, collection: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """Perform an MGET search against Elasticsearch to find all the VirusTotal reports in the collection.

        Returns:
            A map of the feed type to a list of reports.

        """
        docs_list = []
        id_map = {}
        for feed, data in collection.items():
            for d in data:
                if not HASH_MATCHER.match(d):
                    # Generate the expected document ID
                    d = sha256(d.encode()).hexdigest()
                id_map.setdefault(feed, []).append(d)
                # Add a operation to check every index for the document by ID
                docs_list.extend([{"_id": d, "_index": index} for index in self.indices[feed]])

        search_results = []
        if docs_list:
            # Iterate over searches in batches to avoid HTTP 413 exceptions
            batch_size = 1000
            i = 0
            while i * batch_size < len(docs_list):
                search_results += [
                    r
                    for r in self.client.mget(docs=docs_list[i * batch_size : (i + 1) * batch_size])["docs"]
                    if r.get("found")
                ]
                i += 1

        # Sort results by the most recent analysis
        search_results = sorted(
            search_results,
            reverse=True,
            key=lambda x: x["_source"]["attributes"].get(
                "analysis_date", x["_source"]["attributes"].get("last_analysis_date", 0)
            ),
        )

        # Associate reports to ids
        result_manifest = {}
        for type, id_list in id_map.items():
            indices = self.indices.get(type, [])
            report_list = []
            for id in set(id_list):
                for result in search_results:
                    if id == result["_id"] and result["_index"] in indices:
                        report_list.append(result["_source"])
                        break
            result_manifest[type] = report_list
        return result_manifest

    def check_cache(self) -> Optional[str]:
        """Check Elasticsearch to see if the number of documents in the cache has changed.

        Returns:
            A string that's used to invalidate the result cache.

        """
        # Check all the indices used to calculate caching
        all_aliases = []
        for alias in self.index_aliases.values():
            all_aliases += alias
        all_aliases = list(set(all_aliases))

        total_docs = self.client.indices.stats(index=all_aliases, metric="docs", filter_path="_all.total.docs.count")[
            "_all"
        ]["total"]["docs"]["count"]
        if self.total_docs != total_docs:
            # DB has changed since last check

            # Re-calculate the indices that are assigned to each feed
            for feed, aliases in self.index_aliases.items():
                self.indices[feed] = list(
                    set([i["index"] for i in self.client.cat.indices(index=",".join(aliases), format="json")])
                )
            # Update the cached value of the total documents stored
            self.total_docs = total_docs
            return now_as_iso()
