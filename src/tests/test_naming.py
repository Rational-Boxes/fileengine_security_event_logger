from audit_service.naming import schema_for_tenant, validate_schema_name


def test_empty_tenant_is_default():
    assert schema_for_tenant("") == "tenant_default"
    assert schema_for_tenant(None or "") == "tenant_default"


def test_simple_tenant():
    assert schema_for_tenant("acme") == "tenant_acme"


def test_non_word_chars_stripped_like_core():
    # std::isalnum (C locale) strips '-', '.', ' ' — they are removed, not mapped.
    assert schema_for_tenant("ac-me") == "tenant_acme"
    assert schema_for_tenant("ac.me") == "tenant_acme"
    assert schema_for_tenant("ac me") == "tenant_acme"
    assert schema_for_tenant("a/b\\c") == "tenant_abc"


def test_underscores_preserved():
    assert schema_for_tenant("big_corp") == "tenant_big_corp"


def test_truncated_to_63():
    long = "x" * 100
    out = schema_for_tenant(long)
    assert len(out) == 63
    assert out.startswith("tenant_x")


def test_unicode_stripped_to_ascii():
    # C-locale isalnum rejects non-ASCII; the Python port must too.
    assert schema_for_tenant("café") == "tenant_caf"


def test_leading_non_word_is_stripped_like_core():
    # The core strips non-[A-Za-z0-9_] first, so a leading '-' is simply removed
    # (its "prefix _" branch is unreachable — after stripping, the first char is
    # always a word char). The Python port must behave identically.
    assert validate_schema_name("-weird") == "weird"


def test_leading_underscore_preserved():
    assert validate_schema_name("_weird") == "_weird"
