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
        hit_threshold: int = 0,
    ):
        """Initialize the AVResultsProcessor."""
        self.term_blocklist = term_blocklist
        self.revised_sig_score_map = revised_sig_score_map
        self.revised_kw_score_map = revised_kw_score_map
        [self.revised_kw_score_map.update({sig: 0}) for sig in sig_safelist]
        self.specified_AVs = specified_AVs
        self.hit_threshold = hit_threshold

    # Create a results section based on VT reports
    def get_av_results(self, report: Dict[str, Any], score_report: bool = True) -> ResultSection:
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
            analysis_stats = report["attributes"]["last_analysis_stats"]

            # Only raise the heurstic if the number of malicious and suspicious results is above the threshold
            raise_heuristic = (
                analysis_stats.get("malicious", 0) + analysis_stats.get("suspicious", 0) > self.hit_threshold
            )
            heuristic = (
                Heuristic(1 if report_type == "file" else 2)
                if raise_heuristic and category_score and score_report
                else None
            )

            av_categories.setdefault(
                category,
                ResultTableSection(
                    f'Detected "{report["id"] if report_type != "url" else report["attributes"]["url"]}"'
                    f" as: {category.title()}",
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
                tag_type = None
                if report_type == "url":
                    tag_type = "network.static.uri"
                elif report_type == "domain":
                    tag_type = "network.static.domain"
                elif report_type == "ip_address":
                    tag_type = "network.static.ip"

                if tag_type:
                    category_section.add_tag(
                        tag_type,
                        report["attributes"].get("url", report["id"]),
                    )

            if not category_section.heuristic and heuristic:
                # Assign the heuristic to the section if it was not already assigned
                category_section.set_heuristic(heuristic)

            # Only add signatures to the heuristic if they have a score
            if category_section.heuristic:
                category_section.heuristic.add_signature_id(sig, score=category_score)

        # Add all categorized AV results to the main section if there is content in the section
        for _, section in sorted(av_categories.items(), key=lambda x: CATEGORY_SCORING.get(x[0], 0), reverse=True):
            if not section.body:
                # Skip empty sections
                continue
            section.set_column_order(["Result", "Engine Name", "Engine Version", "Engine Update"])
            av_section.add_subsection(section)

        return av_section
