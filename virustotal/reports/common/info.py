import json
import regex

from typing import Any

from assemblyline.odm import IP_ONLY_REGEX, DOMAIN_ONLY_REGEX, FULL_URI
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection, ResultJSONSection, Heuristic


# Modeling output after PDFId service
def pdf_section(info={}, exiftool={}):
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
def pe_section(info={}, exiftool={}, signature={}):
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
    header = ResultSection(
        "PE: HEADER",
        body=json.dumps(header_body),
        body_format=BODY_FORMAT.KEY_VALUE,
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
            imports.add_subsection(ResultSection(f"[{imp['library_name']}]", body=", ".join(imp["imported_functions"])))

    # RESOURCES-VersionInfo
    if signature:
        ResultSection(
            "PE: RESOURCES", body=json.dumps(signature), body_format=BODY_FORMAT.KEY_VALUE, parent=main_section
        )

    return main_section

def malware_config_section(malware_config={}):
    tags = {}
    heur = None
    def tag_output(output: Any, tags: dict = {}):
        def tag_string(value):
            if regex.search(IP_ONLY_REGEX, value):
                tags.setdefault("network.static.ip", []).append(value)
            elif regex.search(DOMAIN_ONLY_REGEX, value):
                tags.setdefault("network.static.domain", []).append(value)
            elif regex.search(FULL_URI, value):
                tags.setdefault("network.static.uri", []).append(value)

        if isinstance(output, dict):
            # Iterate over values of dictionary
            for value in output.values():
                if isinstance(value, dict):
                    tag_output(value, tags)
                elif isinstance(value, list):
                    [tag_output(v, tags) for v in value]
                elif isinstance(value, str):
                    tag_string(value)

        elif isinstance(output, str):
            tag_string(output)

    # Add tags for attribution
    for k, v in malware_config.items():
        if "campaign" in k:
            tags.setdefault("attribution.campaign", []).append(v)
        elif "family" in k:
            tags.setdefault("attribution.family", []).append(v)
        elif "domain" in k:
            tags.setdefault("attribution.network", []).append(v)

        if not heur and ("campaign" in k or "family" in k):
            heur = Heuristic(1002)

    # Tag anything resembling an IP, domain, or URI
    tag_output(malware_config, tags)
    return ResultJSONSection("Malware Configuration", section_body=malware_config, tags=tags, heuristic=heur)

# Modeling output after YARA service
def yara_section(rule_matches=[]):
    yara_section = ResultSection("Crowdsourced YARA")
    for rule in rule_matches:
        section_body = {"ID": rule["ruleset_id"], "Name": rule["rule_name"], "Source": rule["source"]}

        if rule.get("author"):
            section_body["Author"] = rule["author"]
        if rule.get("description"):
            section_body["Description"] = rule["description"]

        yara_section.add_subsection(
            ResultSection(
                title_text=f"[{rule['ruleset_name'].upper()}] {rule['rule_name']}",
                body=json.dumps(section_body),
                body_format=BODY_FORMAT.KEY_VALUE,
            )
        )
    return yara_section
