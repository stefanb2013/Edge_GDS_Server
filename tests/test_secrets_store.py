from gds import secrets_store


def test_load_or_create_key_is_idempotent(tmp_path):
    key1 = secrets_store.load_or_create_key(tmp_path)
    key2 = secrets_store.load_or_create_key(tmp_path)
    assert key1 == key2


def test_encrypt_decrypt_roundtrip(tmp_path):
    key = secrets_store.load_or_create_key(tmp_path)
    token = secrets_store.encrypt(key, "hunter2")
    assert token != "hunter2"
    assert secrets_store.decrypt(key, token) == "hunter2"


def test_decrypt_fails_with_wrong_key(tmp_path):
    key1 = secrets_store.load_or_create_key(tmp_path / "a")
    key2 = secrets_store.load_or_create_key(tmp_path / "b")
    token = secrets_store.encrypt(key1, "hunter2")
    try:
        secrets_store.decrypt(key2, token)
        assert False, "expected InvalidToken"
    except secrets_store.InvalidToken:
        pass
