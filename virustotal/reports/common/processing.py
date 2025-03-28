"""Module for processing AV results from VirusTotal."""

import time
from typing import Any, Dict, List

from assemblyline.common import forge
from assemblyline_v4_service.common.result import Heuristic, ResultSection, ResultTableSection, TableRow

Classification = forge.get_classification()

CATEGORY_SCORING = {"suspicious": 300, "malicious": 1000}


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
            ResultSection: A ResultSection containing the AV reports

        """
        av_section = ResultSection("Analysis Results")
        av_categories: Dict[str, ResultTableSection] = {}
        report_type = report["type"]
        # Create a table of the AV result with null results showing up at the bottom of the table
        for av_details in report["attributes"]["last_analysis_results"].values():
            category = av_details["category"]
            category_score = CATEGORY_SCORING.get(category, 0)
            av_categories.setdefault(
                category,
                ResultTableSection(
                    f'Detected "{report["id"] if report_type != "url" else report["attributes"]["url"]}"'
                    f" as: {category.title()}",
                    heuristic=Heuristic(1 if report_type == "file" else 2) if category_score else None,
                    auto_collapse=not category_score,
                ),
            )
            category_section = av_categories[category]

            av = av_details["engine_name"]
            sig = f"{av}.{av_details['result']}"
            if any(term in sig for term in self.term_blocklist):
                # Term found in signature combination that we wish to block
                continue

            if self.specified_AVs and av not in self.specified_AVs:
                # We only want results from specific AVs
                continue

            category_section.add_row(
                TableRow(
                    {k.replace("_", " ").title(): v for k, v in av_details.items() if k not in ["category", "method"]}
                )
            )

            # Only include AV tags if the report is a file
            if report_type == "file":
                category_section.add_tag("av.virus_name", av_details["result"])
            else:
                category_section.add_tag(
                    f"network.static.{report_type if report_type != 'url' else 'uri'}",
                    report["attributes"].get("url", report["id"]),
                )

            # Only add signatures to the heuristic if they have a score
            if category_section.heuristic:
                category_section.heuristic.add_signature_id(sig, score=category_score)

        # Add all categorized AV results to the main section
        for _, section in sorted(av_categories.items(), key=lambda x: CATEGORY_SCORING.get(x[0], 0), reverse=True):
            section.set_column_order(["Result", "Engine Name", "Engine Version", "Engine Update"])
            av_section.add_subsection(section)

        return av_section
