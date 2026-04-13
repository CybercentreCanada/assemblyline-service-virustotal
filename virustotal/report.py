import base64
import gzip
import io
import json
from typing import Any, Dict

from assemblyline.odm.messages.task import FileInfo


def _zip_text(text_input: str) -> str:
    buf = io.BytesIO()

    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as f:
        f.write(text_input.encode("utf-8"))

    compressed_bytes = buf.getvalue()
    base64_encoded = base64.b64encode(compressed_bytes).decode("utf-8")

    return base64_encoded


def _prune_vt3_summary(file: Dict[str, Any], fileinfo: FileInfo) -> Dict[str, Any]:
    def prune_entry(e):
        return {k: v for k, v in e.items() if k in {"engine_name", "engine_version", "category", "result", "method"}}

    return {
        "type": "file",
        "attributes": {
            "md5": fileinfo.md5,
            "sha1": fileinfo.sha1,
            "sha256": fileinfo.sha256,
            "last_analysis_results": {
                k: prune_entry(v) for k, v in file["attributes"]["last_analysis_results"].items()
            },
        },
    }


def package_scan_report(vt3_results: Dict[str, Any], fileinfo: FileInfo) -> str:
    return _zip_text(json.dumps([_prune_vt3_summary(f, fileinfo) for f in vt3_results]))
