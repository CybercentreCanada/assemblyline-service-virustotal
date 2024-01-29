from reports import ip_domain, url


def test_ip_domain_report():
    # Omitting last_analysis_* data shouldn't cause a crash
    data = {
        "attributes": {
            # "last_analysis_results": {
            #     "test": {"category": "undetected", "result": "test", "method": "blacklist", "engine_name": "test"},
            # },
            # "last_analysis_date": 0,
            "last_modification_date": 0,
            # "reputation": 0,
            "url": "www.google.com",
        },
        "type": "domain",
        "id": "www.google.com",
        "links": {"self": "www.virustotal.com/ui/domains/www.google.com"},
    }

    ip_domain.v3(doc=data)


def test_url_report():
    # Omitting last_analysis_* data shouldn't cause a crash
    data = {
        "attributes": {
            # "last_analysis_results": {
            #     "test": {"category": "undetected", "result": "test", "method": "blacklist", "engine_name": "test"},
            # },
            # "last_analysis_date": 0,
            # "first_submission_date": 0,
            # "last_submission_date": 0,
            # "reputation": 0,
            "url": "https://www.google.com/",
        },
        "type": "url",
        "id": "d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86",
        "links": {
            "self": "https://www.virustotal.com/ui/urls/d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86"
        },
    }

    url.v3(doc=data)
