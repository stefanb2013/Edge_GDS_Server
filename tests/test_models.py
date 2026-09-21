from gds.models import ApplicationRecord


def _app(discovery_urls):
    return ApplicationRecord(
        id="1", application_uri="urn:test:app", application_name="App",
        application_type=0, product_uri="", discovery_urls=discovery_urls,
    )


def test_discovery_hosts_extracts_host_and_port():
    app = _app(["opc.tcp://192.168.0.2:4840/gds/"])
    assert app.discovery_hosts == ["192.168.0.2:4840"]


def test_discovery_hosts_handles_hostname_without_port():
    app = _app(["opc.tcp://plc.local/gds/"])
    assert app.discovery_hosts == ["plc.local"]


def test_discovery_hosts_multiple_urls():
    app = _app(["opc.tcp://192.168.0.2:4840/gds/", "opc.tcp://10.0.0.5:4841/gds/"])
    assert app.discovery_hosts == ["192.168.0.2:4840", "10.0.0.5:4841"]


def test_discovery_hosts_empty_when_no_urls():
    app = _app([])
    assert app.discovery_hosts == []


def test_discovery_hosts_skips_unparseable_url():
    app = _app(["not a url", "opc.tcp://192.168.0.2:4840/gds/"])
    assert app.discovery_hosts == ["192.168.0.2:4840"]
