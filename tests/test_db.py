import pytest

from gds import db
from gds.models import ApplicationStatus


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    db.init_db(tmp_path / "gds_test.db")
    yield


def test_create_and_get_application():
    app = db.create_application("urn:test:a1", "App One", 0, "urn:test:product")
    assert app.status == ApplicationStatus.PENDING
    fetched = db.get_application(app.id)
    assert fetched.application_uri == "urn:test:a1"


def test_reregistering_same_uri_updates_not_duplicates():
    a1 = db.create_application("urn:test:dup", "First Name", 0)
    a2 = db.create_application("urn:test:dup", "Second Name", 0)
    assert a1.id == a2.id
    assert db.get_application_by_uri("urn:test:dup").application_name == "Second Name"
    assert len(db.find_applications()) == 1


def test_find_applications_by_substring():
    db.create_application("urn:acme:server1", "Server 1", 0)
    db.create_application("urn:other:server2", "Server 2", 0)
    results = db.find_applications("acme")
    assert len(results) == 1
    assert results[0].application_uri == "urn:acme:server1"


def test_set_application_status_and_gate():
    app = db.create_application("urn:test:gate", "Gate App", 0)
    assert app.status == ApplicationStatus.PENDING
    db.set_application_status(app.id, ApplicationStatus.APPROVED)
    assert db.get_application(app.id).status == ApplicationStatus.APPROVED


def test_delete_application_cascades_certificates():
    app = db.create_application("urn:test:del", "Del App", 0)
    db.add_certificate(app.id, "abc123", "CN=x", "2020-01-01", "2030-01-01", "PEMDATA")
    assert len(db.list_certificates(app.id)) == 1
    db.delete_application(app.id)
    assert db.get_application(app.id) is None
    assert db.list_certificates(app.id) == []


def test_certificate_lifecycle():
    app = db.create_application("urn:test:cert", "Cert App", 0)
    cert = db.add_certificate(app.id, "serial1", "CN=cert", "2020-01-01", "2030-01-01", "PEMDATA")
    assert cert.status == "active"
    active = db.active_certificates_for(app.id, "DefaultApplicationGroup")
    assert len(active) == 1

    db.revoke_certificate(cert.id)
    assert db.get_certificate(cert.id).status == "revoked"
    assert db.active_certificates_for(app.id, "DefaultApplicationGroup") == []
    assert cert.serial_number in [c.serial_number for c in db.all_revoked_certificates()]


def test_trust_list_entries():
    entry = db.add_trust_list_entry("trusted_cert", "Some CA", "PEMDATA")
    assert db.list_trust_list_entries("trusted_cert")[0].id == entry.id
    db.delete_trust_list_entry(entry.id)
    assert db.list_trust_list_entries("trusted_cert") == []


def test_push_device_lifecycle():
    device = db.create_push_device(
        "PLC 1", "opc.tcp://192.168.0.2:4840",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", "SignAndEncrypt",
        "Admin", "encrypted-blob", True, True,
    )
    assert device.last_test_status == "untested"
    assert device.last_push_status == "never"
    assert db.get_push_device(device.id).name == "PLC 1"
    assert len(db.list_push_devices()) == 1

    db.record_push_device_test(device.id, "success", "Connected fine")
    fetched = db.get_push_device(device.id)
    assert fetched.last_test_status == "success"
    assert fetched.last_test_message == "Connected fine"
    assert fetched.last_test_at is not None

    db.record_push_device_push(device.id, "failed", "BadCertificateUseNotAllowed")
    fetched = db.get_push_device(device.id)
    assert fetched.last_push_status == "failed"
    assert fetched.last_push_message == "BadCertificateUseNotAllowed"

    # Editing without a new password keeps the stored (encrypted) one.
    db.update_push_device(
        device.id, "PLC 1 renamed", device.endpoint_url, device.security_policy_uri,
        device.security_mode, "Admin2", True, False, password_encrypted=None,
    )
    fetched = db.get_push_device(device.id)
    assert fetched.name == "PLC 1 renamed"
    assert fetched.username == "Admin2"
    assert fetched.trust_ca_on_device is False
    assert fetched.password_encrypted == "encrypted-blob"

    db.delete_push_device(device.id)
    assert db.get_push_device(device.id) is None


def test_settings_kv_and_apply_persisted_settings():
    from gds.config import Settings

    assert db.get_setting("issued_cert_valid_days") is None
    db.set_setting("issued_cert_valid_days", "365")
    db.set_setting("renew_before_days", "45")
    assert db.get_setting("issued_cert_valid_days") == "365"
    assert db.all_settings() == {"issued_cert_valid_days": "365", "renew_before_days": "45"}

    # Overwriting an existing key updates it in place, not a duplicate row.
    db.set_setting("issued_cert_valid_days", "180")
    assert db.get_setting("issued_cert_valid_days") == "180"

    settings = Settings()
    original_crl_days = settings.crl_validity_days
    db.apply_persisted_settings(settings)
    assert settings.issued_cert_valid_days == 180
    assert settings.renew_before_days == 45
    assert settings.crl_validity_days == original_crl_days  # untouched: never set


def test_apply_persisted_settings_handles_bool_settings():
    from gds.config import Settings

    settings = Settings()
    assert settings.push_auto_reprovision_enabled is True  # default

    db.set_setting("push_auto_reprovision_enabled", "0")
    db.set_setting("push_health_check_interval_seconds", "600")
    db.apply_persisted_settings(settings)
    assert settings.push_auto_reprovision_enabled is False
    assert settings.push_health_check_interval_seconds == 600

    db.set_setting("push_auto_reprovision_enabled", "1")
    db.apply_persisted_settings(settings)
    assert settings.push_auto_reprovision_enabled is True


def test_user_management_lifecycle():
    import sqlite3

    from gds.models import Role

    admin = db.create_user("admin", "hash1", Role.ADMIN, True)
    assert admin.role == Role.ADMIN
    assert admin.must_change_password is True
    assert db.count_admins() == 1

    with pytest.raises(sqlite3.IntegrityError):
        db.create_user("admin", "hash2")

    operator = db.create_user("operator", "hash3", Role.USER, True)
    assert db.count_admins() == 1
    assert len(db.list_users()) == 2

    db.set_user_password("operator", "hash4", False)
    assert db.get_user("operator").password_hash == "hash4"
    assert db.get_user("operator").must_change_password is False

    db.set_user_role("operator", Role.ADMIN)
    assert db.get_user("operator").role == Role.ADMIN
    assert db.count_admins() == 2

    db.delete_user("operator")
    assert db.get_user("operator") is None
    assert db.count_admins() == 1


def test_users_and_counts():
    assert db.any_users_exist() is False
    db.create_user("admin", "hash123")
    assert db.any_users_exist() is True
    user = db.get_user("admin")
    assert user.password_hash == "hash123"

    db.create_application("urn:test:c1", "C1", 0)
    app2 = db.create_application("urn:test:c2", "C2", 0)
    db.set_application_status(app2.id, ApplicationStatus.APPROVED)
    counts = db.counts()
    assert counts["applications"]["pending"] == 1
    assert counts["applications"]["approved"] == 1
