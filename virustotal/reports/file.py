"""Module for processing file reports from VirusTotal API v3."""

import json

from assemblyline.common import forge
from assemblyline.odm.models.ontology.results import Antivirus
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, ResultSection

from virustotal.reports.common import info
from virustotal.reports.common.configs import CAPABILITY_LOOKUP
from virustotal.reports.common.processing import AVResultsProcessor, format_time_from_epoch

Classification = forge.get_classification()


def v3(doc, file_name, av_processor: AVResultsProcessor) -> ResultSection:
    """Create a ResultSection for a file report from VirusTotal API v3.

    Returns:
        ResultSection: A ResultSection containing the file report

    """
    attributes = doc.get("attributes", {})
    context = doc.get("context_attributes", {})

    heuristic = None
    if attributes.get("capabilities_tags", None):
        heuristic = Heuristic(1000)
        for c in attributes["capabilities_tags"]:
            heuristic.add_attack_id(CAPABILITY_LOOKUP[c])

    main_section = ResultSection(
        f"{attributes.get('meaningful_name', file_name)}",
        heuristic=heuristic,
        classification=Classification.UNRESTRICTED,
        tags={"file.name.extracted": attributes.get("names", [])},
    )

    # Submission meta
    ResultSection(
        "VirusTotal Statistics",
        body=json.dumps(
            {
                "First Seen": format_time_from_epoch(attributes["first_submission_date"]),
                "Last Seen": format_time_from_epoch(attributes["last_submission_date"]),
                "Scan Date": format_time_from_epoch(attributes["last_analysis_date"]),
                "Community Reputation": attributes["reputation"],
                "Permalink": f"https://www.virustotal.com/gui/file/{doc['id']}",
            }
        ),
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

    # *_info Section
    info_found = any("_info" in k for k in attributes.keys()) or any(
        [attributes.get(x) for x in ["crowdsourced_yara_results", "crowdsourced_ai_results"]]
    )
    if info_found:
        info_section = ResultSection("Info Section", auto_collapse=True)
        for k, v in attributes.items():
            if "pe_info" in k:
                info_section.add_subsection(
                    info.pe_section(v, attributes.get("exiftool", {}), attributes.get("signature_info", {}))
                )
            elif "pdf_info" in k:
                info_section.add_subsection(info.pdf_section(v, attributes.get("exiftool", {})))

            # YARA sources
            elif "crowdsourced_yara_results" in k:
                info_section.add_subsection(info.yara_section(v))

            elif "crowdsourced_ai_results" in k:
                [
                    ResultSection(
                        title_text=f"Code Insight by {s['source']}",
                        body=s["analysis"],
                        heuristic=Heuristic(1001),
                        auto_collapse=True,
                        parent=info_section,
                    )
                    for s in v
                ]
        if info_section.subsections:
            main_section.add_subsection(info_section)

    # Malware Config
    if attributes.get("malware_config"):
        info_section.add_subsection(info.malware_config_section(attributes["malware_config"]))

    infected_section, no_av_section = av_processor.get_av_results(attributes["last_analysis_results"])
    if infected_section.subsections:
        main_section.add_subsection(infected_section)
        main_section.add_subsection(no_av_section)
    return main_section


def attach_ontology(ontology_helper: None, doc: dict):
    """Attach the ontology of the VirusTotal file report."""
    av_results = doc["attributes"]["last_analysis_results"]
    for details in av_results.values():
        result = details["result"]
        if result == "timeout":
            result = None
        elif details["category"] in ["timeout", "confirmed-timeout"]:
            # Not reporting on timeouts
            continue
        details["virus_name"] = result or "undetected"
        details["engine_definition_version"] = details["engine_update"]
        if details.get("engine_version") == "":
            # Invalid engine_version
            details.pop("engine_version")
        # Pop irrelevant fields to ontology
        [details.pop(x, None) for x in ["result", "method", "engine_update"]]
        ontology_helper.add_result_part(Antivirus, details)
