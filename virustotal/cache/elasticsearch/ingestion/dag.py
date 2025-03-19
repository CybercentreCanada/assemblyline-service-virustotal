"""Airflow DAG for pulling and ingesting VirusTotal feeds."""

from datetime import timedelta

from airflow.models.dag import DAG
from airflow.utils.dates import days_ago
from daggers.operators import GitPythonOperator

default_args = {
    "owner": "CybercentreCanada",
    "depends_on_past": False,
    "start_date": days_ago(0),
    "email_on_failure": True,
    "email_on_retry": False,
    "retries": 3,
    "retry_delay": timedelta(minutes=1),
}

dag = DAG(
    dag_id="virustotalcache_pull_and_ingest_feeds",
    default_args=default_args,
    schedule_interval="*/15 * * * *",
    catchup=True,
)

pull_url = GitPythonOperator(
    task_id="vtc_pull_urls",
    dag=dag,
    provide_context=True,
    repo_url="https://github.com/CybercentreCanada/assemblyline-service-virustotal.git",
    run_module="virustotal.cache.elasticsearch.ingestion.ingest",
    run_method="main",
    run_kwargs={"feed_type": "urls", "period": 15},
    is_venv=True,
)

pull_file = GitPythonOperator(
    task_id="vtc_pull_files",
    dag=dag,
    provide_context=True,
    repo_url="https://github.com/CybercentreCanada/assemblyline-service-virustotal.git",
    run_module="virustotal.cache.elasticsearch.ingestion.ingest",
    run_method="main",
    run_kwargs={"feed_type": "files", "period": 15},
    is_venv=True,
)

pull_ip = GitPythonOperator(
    task_id="vtc_pull_ips",
    dag=dag,
    provide_context=True,
    repo_url="https://github.com/CybercentreCanada/assemblyline-service-virustotal.git",
    run_module="virustotal.cache.elasticsearch.ingestion.ingest",
    run_method="main",
    run_kwargs={"feed_type": "ip_addresses", "period": 15},
    is_venv=True,
)

pull_domain = GitPythonOperator(
    task_id="vtc_pull_domains",
    dag=dag,
    provide_context=True,
    repo_url="https://github.com/CybercentreCanada/assemblyline-service-virustotal.git",
    run_module="virustotal.cache.elasticsearch.ingestion.ingest",
    run_method="main",
    run_kwargs={"feed_type": "domains", "period": 15},
    is_venv=True,
)

pull_behaviour = GitPythonOperator(
    task_id="vtc_pull_behaviours",
    dag=dag,
    provide_context=True,
    repo_url="https://github.com/CybercentreCanada/assemblyline-service-virustotal.git",
    run_module="virustotal.cache.elasticsearch.ingestion.ingest",
    run_method="main",
    run_kwargs={"feed_type": "file-behaviours", "period": 15},
    is_venv=True,
)

pull_url, pull_file, pull_ip, pull_domain, pull_behaviour
