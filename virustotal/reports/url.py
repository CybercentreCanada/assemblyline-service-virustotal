"""Module for VirusTotal URL reports."""

from assemblyline.common import forge
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.result import (
    KVSectionBody,
    ResultKeyValueSection,
    ResultMultiSection,
    ResultSection,
    ResultTextSection,
    URLSectionBody,
)

from virustotal.reports.common.processing import AVResultsProcessor, format_time_from_epoch

Classification = forge.get_classification()


def v3(doc: dict, av_processor: AVResultsProcessor, score_report: bool = True) -> ResultSection:
    """Create a ResultSection for a URL report from VirusTotal API v3.

    Returns:
        ResultSection: A ResultSection containing the URL report

    """
    attributes = doc.get("attributes", {})
    context = doc.get("context_attributes", {})

    # Submission meta
    categories = list(set([v.lower() for v in attributes.get("categories", {}).values()]))
    body_dict = {"Categories": ", ".join(categories)}
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

    main_section = ResultTextSection(section_title)

    # Submission meta
    meta_section = ResultMultiSection(
        "VirusTotal Statistics",
        parent=main_section,
        classification=Classification.UNRESTRICTED,
    )

    # Statistics data
    meta_section.add_section_part(KVSectionBody(**body_dict))

    # Permalink
    permalink_section = URLSectionBody()
    permalink_section.add_url(f"https://www.virustotal.com/gui/url/{doc['id']}")
    meta_section.add_section_part(permalink_section)

    submitter = context.get("submitter", None)
    if submitter:
        ResultKeyValueSection(
            "Submitter details",
            body=submitter,
            classification=Classification.RESTRICTED,
            parent=main_section,
        )

    # Tags
    if score_report:
        main_section.add_tag("network.static.uri", attributes["url"])

    detection_section, collapse_parent = av_processor.get_av_results(doc, score_report)
    if detection_section.subsections:
        main_section.add_subsection(detection_section)

    main_section.auto_collapse = collapse_parent

    return main_section


def attach_ontology(helper: OntologyHelper, doc: dict):
    """Attach the VirusTotal URL report to the ontology."""
    return
