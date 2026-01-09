"""Module for processing AV results from VirusTotal."""

import time
from typing import Any, Dict, List, Tuple

from assemblyline.common import forge
from assemblyline_v4_service.common.result import (
    Heuristic,
    ResultJSONSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

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
    ) -> Tuple[ResultSection, bool]:
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
        av_section = ResultTextSection("Analysis Results")
        av_categories: Dict[str, ResultTableSection] = {}
        report_type = report["type"]
        analysis_stats = {}

        # Determine tag type and value based on report type
        tag_type = None
        tag_value = report["attributes"].get("url", report["id"])
        if report_type == "url":
            tag_type = "network.static.uri"
        elif report_type == "domain":
            tag_type = "network.static.domain"
        elif report_type == "ip_address":
            tag_type = "network.static.ip"

        # Apply filter on reports based on term blocklist and specified AVs before processing
        last_analysis_results = []
        for av_details in report["attributes"]["last_analysis_results"].values():
            sig = f"{av_details['engine_name']}.{av_details['result']}"
            if any(term in sig for term in self.term_blocklist):
                # Term found in signature combination that we wish to block
                continue

            if self.specified_AVs and av_details["engine_name"] not in self.specified_AVs:
                # We only want results from specific AVs
                continue

            analysis_stats.setdefault(av_details["category"], 0)
            analysis_stats[av_details["category"]] += 1

            last_analysis_results.append(av_details)

        # Create a table of the AV result with null results showing up at the bottom of the table
        for av_details in last_analysis_results:
            category = av_details["category"]
            category_score = CATEGORY_SCORING.get(category, 0)

            av_categories.setdefault(
                category,
                ResultTableSection(
                    f'Detected "{report["id"] if report_type != "url" else report["attributes"]["url"]}"'
                    f" as: {category.title()}",
                    auto_collapse=not category_score,
                ),
            )
            category_section = av_categories[category]
            category_section.add_row(
                TableRow(
                    {k.replace("_", " ").title(): v for k, v in av_details.items() if k not in ["category", "method"]}
                )
            )

            # Only include AV tags if the report is a file
            if report_type == "file":
                category_section.add_tag("av.virus_name", av_details["result"])
            else:
                # Include general network tags for non-file reports
                category_section.add_tag(tag_type, tag_value)

        # Add scoring heuristic to the main AV section depending on presence of GTI assessment
        collapse_parent = True
        if "gti_assessment" in report["attributes"]:
            # GTI assessment present, lower the threshold for raising the heuristic
            gti_assessment = report["attributes"]["gti_assessment"]
            verdict = gti_assessment["verdict"]["value"][8:]
            if tag_type:
                # Add tags based on GTI assessment verdict
                av_section.add_tag(tag_type, tag_value)
            # Check if an analyst has already reviewed the GTI assessment which is more reliable
            if gti_assessment.get("contributing_factors", {}).get("mandiant_analyst_benign"):
                verdict = "BENIGN"
            elif gti_assessment.get("contributing_factors", {}).get("mandiant_analyst_malicious"):
                verdict = "MALICIOUS"

            if gti_assessment["severity"]["value"] == "SEVERITY_LOW" and report_type != "file":
                # Low severity diminishes the verdict's impact for non-file reports
                if verdict == "MALICIOUS":
                    verdict = "SUSPICIOUS"
                elif verdict == "SUSPICIOUS":
                    verdict = "UNKNOWN"

            if verdict in ["SUSPICIOUS", "MALICIOUS"] and score_report:
                heuristic = Heuristic(1 if report_type == "file" else 2, signature=verdict.lower())
                collapse_parent = False
                av_section.set_heuristic(heuristic)

            # Include a body to the section to show the GTI assessment details
            av_section.set_body(
                f"GTI Assessment: {gti_assessment['verdict']['value'][8:]} verdict "
                f"with {gti_assessment['severity']['value'][9:]} severity.\n"
                f"Resolution: {verdict}"
            )

            # Add raw GTI assessment details as a JSON subsection
            section = ResultJSONSection("GTI Assessment", parent=av_section, auto_collapse=True)
            section.set_json(gti_assessment)

        else:
            # No GTI assessment, use the hit threshold
            av_section.set_body("No GTI Assessment present.")
            raise_heuristic = analysis_stats.get("malicious", 0) >= self.hit_threshold
            for category, category_section in av_categories.items():
                category_score = CATEGORY_SCORING.get(category, 0)
                heuristic = (
                    Heuristic(1 if report_type == "file" else 2)
                    if raise_heuristic and category_score and score_report
                    else None
                )

                if heuristic:
                    # Only add signatures to the heuristic if they have a score
                    for av_details in last_analysis_results:
                        if av_details["category"] != category:
                            continue

                        heuristic.add_signature_id(
                            f"{av_details['engine_name']}.{av_details['result']}", score=category_score
                        )
                    collapse_parent = False

                category_section.set_heuristic(heuristic)

        # Add all categorized AV results to the main section if there is content in the section
        for _, section in sorted(av_categories.items(), key=lambda x: CATEGORY_SCORING.get(x[0], 0), reverse=True):
            if not section.body:
                # Skip empty sections
                continue
            section.set_column_order(["Result", "Engine Name", "Engine Version", "Engine Update"])
            av_section.add_subsection(section)

        return av_section, collapse_parent
