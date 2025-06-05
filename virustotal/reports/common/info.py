"""Functions to create ResultSections for the VirusTotal service."""

import json
from typing import Any

import regex
from assemblyline.odm import DOMAIN_ONLY_REGEX, FULL_URI, IP_ONLY_REGEX
from assemblyline_v4_service.common.result import Heuristic, ResultJSONSection, ResultKeyValueSection, ResultSection


# Modeling output after PDFId service
def pdf_section(info={}, exiftool={}) -> ResultSection:
    """Create a ResultSection for PDF information.

    Returns:
        ResultSection: A ResultSection containing the PDF information

    """
    main_section = ResultSection("PDF INFO")
    pdf_properties = ResultSection("PDF Properties", parent=main_section)
    pdf_properties.add_line(f"PDF Header: {info['header']}")
    pdf_properties.add_lines([f"{k.split('num_')[1]}: {v}" for k, v in info.items() if "num_" in k])
    pdf_properties.add_line(f"trailer: {info['trailer']}")
    pdf_properties.add_lines([f"{k}: {v}" for k, v in info.items() if "xref" in k])
    if exiftool:
        if exiftool.get("CreateDate", None):
            pdf_properties.add_line(f"CreationDate: {exiftool['CreateDate']}")
            pdf_properties.add_tag("file.date.creation", exiftool["CreateDate"])
        if exiftool.get("ModifyDate", None):
            pdf_properties.add_line(f"ModifyDate: {exiftool['ModifyDate']}")
            pdf_properties.add_tag("file.pdf.date.modified", exiftool["ModifyDate"])

    return main_section


# Modeling output after PEFile service
def pe_section(info={}, exiftool={}, signature={}) -> ResultSection:
    """Create a ResultSection for PE information.

    Returns:
        ResultSection: A ResultSection containing the PE information

    """
    # HEADER
    main_section = ResultSection("PE INFO")
    header_body = {}
    header_tags = {}
    if signature.get("original name"):
        header_body["Original filename"] = signature["original name"]
        header_tags["file.pe.versions.filename"] = [signature["original name"]]
    if signature.get("description"):
        header_body["Description"] = signature["description"]
        header_tags["file.pe.versions.description"] = [signature["description"]]
    header = ResultKeyValueSection(
        "PE: HEADER",
        body=header_body,
        tags=header_tags,
        parent=main_section,
    )

    #  HEADER INFO
    if exiftool:
        header_info = ResultSection("[HEADER INFO]", parent=header)
        header_info.add_line(f"Entry point address: {exiftool['EntryPoint']}")
        header_info.add_line(f"Linker Version: {exiftool['LinkerVersion']}")
        header_info.add_line(f"OS Version: {exiftool['OSVersion']}")
        header_info.add_line(f"Machine Type: {exiftool['MachineType']}")
        if info.get("timestamp", None):
            header_info.add_line(f"Time Date Stamp: {exiftool['TimeStamp']}({info['timestamp']})")
            header_info.add_tag("file.pe.linker.timestamp", info["timestamp"])
        else:
            header_info.add_line(f"Time Date Stamp: {exiftool['TimeStamp']}")

    #  RICH HEADER INFO
    if info.get("compiler_product_versions", None):
        rich_header_info = ResultSection("[RICH HEADER INFO]", parent=header)
        rich_header_info.add_lines(info["compiler_product_versions"])

    #  SECTIONS
    if info.get("sections", None):
        sections = ResultSection("[SECTIONS]", parent=header)
        for s in info["sections"]:
            section_name = s.get("name", "")
            tags = {"file.pe.sections.hash": [s["md5"]]}
            if section_name:
                tags["file.pe.sections.name"] = [section_name]
            ResultSection(
                f"{section_name} - Virtual: {hex(s['virtual_address'])}({hex(s['virtual_size'])} bytes) - "
                f"Physical: ({hex(s['raw_size'])} bytes) - hash: {s['md5']} - entropy: {s['entropy']}",
                tags=tags,
                parent=sections,
            )

    # DEBUG
    if info.get("debug", None):
        debug = ResultSection("PE: DEBUG", parent=main_section)
        debug.add_line(f"Time Date Stamp: {info['debug'][0]['timestamp']}")
        if info["debug"][0].get("codeview", None):
            name = info["debug"][0]["codeview"].get("name")
            guid = info["debug"][0]["codeview"].get("guid")
            if name:
                debug.add_line(f"PDB: {name}")
                debug.add_tag("file.pe.pdb_filename", name)
            if guid:
                debug.add_line(f"GUID: {guid}")
                debug.add_tag("file.pe.debug.guid", guid)

    # IMPORTS
    if info.get("import_list", None):
        imports = ResultSection("PE: IMPORTS", parent=main_section)
        for imp in info["import_list"]:
            imports.add_subsection(
                ResultSection(
                    f"[{imp['library_name']}]",
                    body=", ".join(imp["imported_functions"]),
                )
            )

    # RESOURCES-VersionInfo
    if signature:
        ResultKeyValueSection(
            "PE: RESOURCES",
            body=signature,
            parent=main_section,
        )

    return main_section


def malware_config_section(malware_config={}) -> ResultSection:
    """Create a ResultSection for malware configuration.

    Returns:
        ResultSection: A ResultSection containing the malware config information

    """
    tags = {}
    heur = None

    def tag_output(output: Any):
        def tag_string(value):
            if regex.search(IP_ONLY_REGEX, value):
                tags.setdefault("network.static.ip", []).append(value)
            elif regex.search(DOMAIN_ONLY_REGEX, value):
                tags.setdefault("network.static.domain", []).append(value)
            elif regex.search(FULL_URI, value):
                tags.setdefault("network.static.uri", []).append(value)

        if isinstance(output, dict):
            # Iterate over values of dictionary
            for key, value in output.items():
                if key == "family":
                    nonlocal heur
                    heur = Heuristic(1002)
                    tags.setdefault("attribution.family", []).append(value)

                if isinstance(value, dict):
                    tag_output(value)
                elif isinstance(value, list):
                    [tag_output(v) for v in value]
                elif isinstance(value, str):
                    tag_string(value)

        elif isinstance(output, str):
            tag_string(output)

    # Tag anything resembling an IP, domain, or URI
    tag_output(malware_config)
    section = ResultJSONSection("Malware Configuration", tags=tags, heuristic=heur)
    section.set_json(malware_config)
    return section


def signature_section(signature_info={}) -> ResultSection:
    """Create a ResultSection for signature information.

    Returns:
        ResultSection: A ResultSection containing the signature information

    """
    key_title_map = {
        "signers details": "Signers",
        "counter signers details": "Counter Signers",
        "x509": "X509 Certificates",
    }
    detail_tag_map = {
        "algorithm": "cert.signature_algo",
        "cert issuer": "cert.issuer",
        "name": "cert.subject",
        "serial number": "cert.serial_no",
        "status": "cert.status",
        "thumbprint": "cert.thumbprint",
        "valid from": "cert.valid.start",
        "valid to": "cert.valid.end",
        "usage": "cert.key_usage",
    }
    section = ResultSection("Signature Info")
    for key, title in key_title_map.items():
        if signature_info.get(key, None):
            subsection = ResultSection(title)
            for detail in signature_info[key]:
                # Add a row for each signature detail in the section
                cert_section = ResultKeyValueSection(detail["name"], body=detail, parent=subsection)

                # Add tags for each detail
                for key, tag in detail_tag_map.items():
                    if key in detail:
                        cert_section.add_tag(tag, detail[key])

            if subsection.subsections:
                # Add the subsection to the main section if it has rows
                section.add_subsection(subsection)

    return section


# Modeling output after YARA service
def yara_section(rule_matches=[]) -> ResultSection:
    """Create a ResultSection for YARA rule matches.

    Returns:
        ResultSection: A ResultSection containing the YARA rule information

    """
    yara_section = ResultSection("Crowdsourced YARA")
    for rule in rule_matches:
        section_body = {
            "ID": rule["ruleset_id"],
            "Name": rule["rule_name"],
            "Source": rule["source"],
        }

        if rule.get("author"):
            section_body["Author"] = rule["author"]
        if rule.get("description"):
            section_body["Description"] = rule["description"]

        yara_section.add_subsection(
            ResultKeyValueSection(
                title_text=f"[{rule['ruleset_name'].upper()}] {rule['rule_name']}",
                body=section_body,
            )
        )
    return yara_section
