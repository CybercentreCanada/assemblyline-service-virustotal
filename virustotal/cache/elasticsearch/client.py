"""Client to interact with Elasticsearch for cached VirusTotal reports."""

import re
from functools import lru_cache
from hashlib import sha256
from os import environ
from time import time
from typing import Dict, List, Optional, Tuple

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.base import SHA256_REGEX
from elasticsearch import Elasticsearch

from virustotal.cache.client import CacheClient

LRU_CACHE_SIZE = int(environ.get("LRU_CACHE_SIZE", "1024"))
HASH_MATCHER = re.compile(SHA256_REGEX)


# Add LRU caching to reduce the number of Elasticsearch queries for repeated requests
@lru_cache(maxsize=LRU_CACHE_SIZE)
def mget(es_client: Elasticsearch, docs: Tuple[Tuple[str, str]], cache: str) -> List[Dict]:
    """Perform an MGET search against Elasticsearch to find all the VirusTotal reports in the collection.

    Returns:
        A list of reports.

    """
    return es_client.mget(docs=[{"_id": _id, "_index": _index} for _id, _index in docs])


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
        self._cached_version: str = None
        self._last_cache_check: int = None

    def bulk_search(self, collection: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """Perform an MGET search against Elasticsearch to find all the VirusTotal reports in the collection.

        Returns:
            A map of the feed type to a list of reports.

        """
        id_map = {}
        search_results = []
        for feed, data in collection.items():
            for d in data:
                if not HASH_MATCHER.match(d):
                    # Generate the expected document ID
                    d = sha256(d.encode()).hexdigest()
                id_map.setdefault(feed, []).append(d)

                # Prepare the list of documents to search for
                docs_list = [(d, index) for index in self.indices[feed]]

                # Iterate over the documents in batches to avoid overwhelming Elasticsearch
                batch_size = 1000
                docs_length = len(docs_list)
                i = 0
                while i * batch_size < docs_length:
                    # Perform the MGET search while using the cached version to reduce redundant searches
                    search_results += [
                        r
                        for r in mget(
                            self.client,
                            docs=tuple(docs_list[i * batch_size : (i + 1) * batch_size]),
                            cache=self._cached_version,
                        )["docs"]
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

    def check_cache(self, interval: int) -> Optional[str]:
        """Check Elasticsearch to see if the number of documents in the cache has changed.

        Returns:
            A string that's used to invalidate the result cache.

        """
        if self._last_cache_check and time() < self._last_cache_check + interval * 60:
            return self._cached_version
        else:
            # Check all the indices used to calculate caching
            self._last_cache_check = time()
            all_aliases = []
            for alias in self.index_aliases.values():
                all_aliases += alias
            all_aliases = list(set(all_aliases))

            total_docs = self.client.indices.stats(
                index=all_aliases, metric="docs", filter_path="_all.total.docs.count"
            )["_all"]["total"]["docs"]["count"]
            if self.total_docs != total_docs:
                # DB has changed since last check

                # Re-calculate the indices that are assigned to each feed
                for feed, aliases in self.index_aliases.items():
                    self.indices[feed] = list(
                        set([i["index"] for i in self.client.cat.indices(index=",".join(aliases), format="json")])
                    )
                # Update the cached value of the total documents stored
                self.total_docs = total_docs
                self._cached_version = now_as_iso()

            return self._cached_version
