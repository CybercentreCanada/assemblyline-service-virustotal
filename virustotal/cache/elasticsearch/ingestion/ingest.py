"""Script to pull data from the VirusTotal feed API and ingest it into an Elasticsearch cluster."""

import bz2
import json
import re
import tempfile
from hashlib import sha256
from time import gmtime, mktime, strftime, strptime, time

import urllib3
import vt
from elasticsearch import Elasticsearch, helpers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ELASTIC_HOST = "http://localhost:9200"
ELASTIC_APIKEY = ""
VT_APIKEY = ""
TIME_OFFSET = 3600  # 1H in seconds

hash_match = re.compile("^[a-fA-F0-9]{64}$")

FEED_INDEX_MAPPING = {
    "files": "virustotal_v3_file",
    "file_behaviours": "virustotal_v3_behaviour",
    "domains": "virustotal_v3_domain",
    "ip_addresses": "virustotal_v3_ip",
    "urls": "virustotal_v3_url",
}

ES = Elasticsearch(hosts=[ELASTIC_HOST], api_key=ELASTIC_APIKEY, timeout=300)


def get_package(feed, period, timestamp, es=ES, vt_apikey=VT_APIKEY):
    """Pull a package from the VirusTotal feed API and ingest it into an Elasticsearch cluster."""
    timestamp = time() if timestamp == 0 else timestamp
    with vt.Client(apikey=vt_apikey) as vt_client:
        with tempfile.NamedTemporaryFile() as extracted_contents:
            current_period = period
            while current_period >= 0:
                # Timestamp to grab
                t = strftime("%Y%m%d%H%M", gmtime(timestamp - TIME_OFFSET - (60 * current_period)))
                print(t)

                # Get package
                vt_resp = vt_client.get(f"/feeds/{feed}/{t}")

                # Write response to file
                with tempfile.NamedTemporaryFile() as temp_archive:
                    temp_archive.write(vt_resp.read())
                    temp_archive.seek(0)

                    # Extract package contents
                    with bz2.open(temp_archive.name, mode="rb") as archive:
                        extracted_contents.write(archive.read())

                current_period -= 1

            with open(extracted_contents.name) as file:
                json_list = [line.strip() for line in file]  # newline separated

        # Write to Elasticsearch
        actions = []
        for doc in json_list:
            doc_id = json.loads(doc)["id"]
            if not hash_match.match(doc_id):
                # Hash the id
                doc_id = sha256(doc_id.encode()).hexdigest()

            actions.append(
                {
                    "_index": FEED_INDEX_MAPPING[feed],
                    "_id": doc_id,
                    "_source": doc,
                    "_op_type": "index",
                }
            )

        if actions:
            try:
                helpers.bulk(es, actions)
            except helpers.BulkIndexError as e:
                print("ERROR: Problem with bulk insert into ES")
                print([(i["index"]["_index"], i["index"]["error"]) for i in e.errors])

                if "disk usage exceeded flood-stage watermark" in str(e):
                    exit(-1)


def main(feed_type="", period=0, **kwargs):
    """Main function to pull and ingest VirusTotal feeds."""  # noqa: D401
    timestamp = 0
    if kwargs.get("context", None) and kwargs["context"].get("execution_date", None):
        # Retrieve the execution date from Airflow context
        timestamp = kwargs["context"]["execution_date"].int_timestamp
    elif kwargs.get("context", None) and kwargs["context"].get("ts_nodash", None):
        # Retrieve the execution date from Airflow context (alternative)
        timestamp = mktime(strptime(kwargs["context"]["ts_nodash"], "%Y%m%dT%H%M%S"))

    print("Pull started.")
    get_package(feed_type, period, timestamp)
    print("Pull complete.")
