"""Module for processing AV results from VirusTotal."""

import time
from typing import Any, Dict, List

from assemblyline.common import forge
from assemblyline_v4_service.common.result import Heuristic, ResultTableSection, TableRow

Classification = forge.get_classification()


def format_time_from_epoch(t):
    """Format time from epoch to human readable format.

    Returns:
        str: Human readable time

    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


class AVResultsProcessor:
    """Class to process AV results from VirusTotal."""

    def __init__(
        self,
        term_blocklist: List[str],
        revised_sig_score_map: Dict[str, int],
        revised_kw_score_map: Dict[str, int],
        sig_safelist: List[str] = [],
        specified_AVs: List[str] = [],
    ):
        """Initialize the AVResultsProcessor."""
        self.term_blocklist = term_blocklist
        self.revised_sig_score_map = revised_sig_score_map
        self.revised_kw_score_map = revised_kw_score_map
        [self.revised_kw_score_map.update({sig: 0}) for sig in sig_safelist]
        self.specified_AVs = specified_AVs

    # Create a results section based on VT reports
    def get_av_results(self, report: Dict[str, Any]) -> ResultTableSection:
        """Create a ResultSection based on AV reports.

        Returns:
            ResultTableSection: A ResultTableSection containing the AV reports

        """
        av_section = ResultTableSection(
            "Analysis Results",
            heuristic=Heuristic(
                1 if report["type"] == "file" else 2, signatures=report["attributes"]["last_analysis_stats"]
            ),
        )
        # Create a table of the AV result with null results showing up at the bottom of the table
        for av_details in sorted(report["attributes"]["last_analysis_results"].values(), key=lambda x: not x["result"]):
            av = av_details["engine_name"]
            sig = f"{av}.{av_details['result']}"
            if any(term in sig for term in self.term_blocklist):
                # Term found in signature combination that we wish to block
                continue

            if self.specified_AVs and av not in self.specified_AVs:
                # We only want results from specific AVs
                continue

            av_section.add_row(TableRow({k.replace("_", " ").title(): v for k, v in av_details.items()}))
            av_section.add_tag("av.virus_name", av_details["result"])

        return av_section
