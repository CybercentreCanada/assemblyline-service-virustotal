"""Module for VirusTotal URL reports."""

import json

from assemblyline.common import forge
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection

from virustotal.reports.common.processing import AVResultsProcessor, format_time_from_epoch

Classification = forge.get_classification()


def v3(doc: dict, av_processor: AVResultsProcessor, score_report: bool = True) -> ResultSection:
    """Create a ResultSection for a URL report from VirusTotal API v3.

    Returns:
        ResultSection: A ResultSection containing the URL report

    """
    attributes = doc.get("attributes", {})
    context = doc.get("context_attributes", {})

    submitter = context.get("submitter", None)
    if submitter:
        submitter = ResultSection(
            "Submitter details",
            body=json.dumps(submitter),
            body_format=BODY_FORMAT.KEY_VALUE,
            classification=Classification.RESTRICTED,
        )

    # Submission meta
    categories = list(set([v.lower() for v in attributes.get("categories", {}).values()]))
    body_dict = {
        "Categories": ", ".join(categories),
        "Permalink": f"https://www.virustotal.com/gui/url/{doc['id']}",
    }
    if attributes.get("last_analysis_date"):
        body_dict["Scan Date"] = format_time_from_epoch(attributes["last_analysis_date"])

    if attributes.get("first_submission_date"):
        body_dict["First Seen"] = format_time_from_epoch(attributes["first_submission_date"])
        body_dict["Last Seen"] = format_time_from_epoch(attributes["last_submission_date"])

    if attributes.get("reputation"):
        body_dict["Reputation"] = attributes["reputation"]

    section_title = attributes["url"]
    if attributes.get("title", None):
        section_title += f" ({attributes['title']})"

    main_section = ResultSection(section_title)

    # Submission meta
    ResultSection(
        "VirusTotal Statistics",
        body=json.dumps(body_dict),
        body_format=BODY_FORMAT.KEY_VALUE,
        parent=main_section,
        classification=Classification.UNRESTRICTED,
    )

    submitter = context.get("submitter", None)
    if submitter:
        ResultSection(
            "Submitter details",
            body=json.dumps(submitter),
            body_format=BODY_FORMAT.KEY_VALUE,
            classification=Classification.RESTRICTED,
            parent=main_section,
        )

    # Tags
    main_section.add_tag("network.static.uri", attributes["url"])

    detection_section = av_processor.get_av_results(doc, score_report)
    if detection_section.subsections:
        main_section.add_subsection(detection_section)

    return main_section


def attach_ontology(helper: OntologyHelper, doc: dict):
    """Attach the VirusTotal URL report to the ontology."""
    return
