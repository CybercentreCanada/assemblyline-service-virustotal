"""Template class for implementing clients that interact with a cache of VirusTotal data."""

from typing import Dict, List


class CacheClient:
    """Abstract of a client that interacts with a cache of VirusTotal data."""

    def check_cache(self) -> str:
        """Invalidate the cache to ensure AL isn't re-using old results unnecessarily."""
        raise NotImplementedError()

    def bulk_search(self, collection: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """Perform a bulk operation of fetching reports from the cache."""
        raise NotImplementedError()
