# VirusTotal Cache (Elasticsearch)

## Cache Setup

### Index Templates

For Assemblyline's use, indexing the fields in the VirusTotal reports isn't a requirement as most of the interaction involves using GETs or MGETs by document ID.

For your convenience, we've included a set of index templates [here](./index_templates).

Note: These templates are defined to use an ILM named `virustotal-policy` which ensures the rollover of data once it's reached a certain size or age. While this is not required for the service, we do consider it best practice for managing your data. See [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management.html) for more information.

### Setting up index write aliases

When creating your first set of indices per feed, it's recommended to assign an alias and specify if the index in question is the write index. This will help with performing a rollover of indices (whether automatic via ILM or manually triggered) as well as grouping your indices under a single alias which the service will use.

For example, to create an index for the file feed, you can use the following request:
```
PUT virustotal_v3_file-000001
{
  "aliases": {
    "virustotal_v3_file": {
      "is_write_index": true
    }
  }
}
```

### Ingestion Process

The service assumes that all document IDs in Elasticsearch are the SHA256 of the VirusTotal `id` field (the exception is the file feed where the `id` is already the SHA256 of the file being reported).
The reason for this is to better facilitate performing MGETs in a uniform manner across all fields as opposed to varying ID formats.

You'll find an [example](./ingestion/ingest.py) of an ingestion script written in Python. The script assumes that you want to gather reports on a minutely basis over a certain period of time.

There is also an [example](./ingestion/dag.py) of an Airflow DAG that you can run on a periodic basis to populate your cache over time. The DAG would use the ingestion script mentioned above but will also pass in contextual information about the run to help with recovering data that wasn't ingested before should the task failed (ie. hit quota limits with VirusTotal). For more information on Airflow, see [here](https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/dags.html).

## Service Configuration

You'll have to add the list of cache configurations to the `cache` configuration of the service. Specifying the `type` is important so the service knows how to initialize the client to interact with your cache.

For example for Elasticsearch:
```yaml
...
config:
  ...
  cache:
    - type: elasticsearch
      params:
        hosts: ["https://elastic:devpass@localhost:9200"]
        apikey: null
        index_aliases:
          file: ["vt_file"]
          url: ["vt_url"]
          ip: ["vt_ip"]
          domain: ["vt_domain"]
```
