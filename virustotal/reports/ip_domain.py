"""Module for VirusTotal IP/Domain reports."""

from assemblyline.common import forge
from assemblyline_v4_service.common.result import ResultKeyValueSection, ResultSection, ResultTextSection

from virustotal.reports.common.processing import AVResultsProcessor, format_time_from_epoch

Classification = forge.get_classification()


def v3(doc: dict, av_processor: AVResultsProcessor, score_report: bool = True) -> ResultSection:
    """Create a ResultSection for a IP/Domain report from VirusTotal API v3.

    Returns:
        ResultSection: A ResultSection containing the IP/Domain report

    """
    attributes = doc.get("attributes", {})

    # Submission meta
    categories = list(set([v.lower() for v in attributes.get("categories", {}).values()]))
    body_dict = {
        "Categories": ", ".join(categories),
        "Permalink": f"https://www.virustotal.com/gui/{doc['type'].replace('_', '-')}/{doc['id']}",
    }
    if attributes.get("reputation"):
        body_dict["Reputation"] = attributes.get("reputation")

    if attributes.get("last_modification_date"):
        body_dict["Last Modification Date"] = format_time_from_epoch(attributes.get("last_modification_date"))

    term = doc["id"]
    main_section = ResultTextSection(term)

    # Submission meta
    ResultKeyValueSection(
        "VirusTotal Statistics",
        body=body_dict,
        parent=main_section,
        classification=Classification.UNRESTRICTED,
    )

    # Tags
    if score_report:
        main_section.add_tag(f"network.static.{doc['type'].split('_')[0].lower()}", term)

    detection_section = av_processor.get_av_results(doc, score_report)
    if detection_section.subsections:
        main_section.add_subsection(detection_section)

    return main_section


def attach_ontology(ontology_helper: None, doc: dict):
    """Attach the VirusTotal IP/Domain report to the ontology."""
    return
