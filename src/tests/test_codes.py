from audit_service import codes


def test_category_values_are_stable():
    assert codes.CATEGORY == {
        "access": 0, "mutate": 1, "permission": 2, "user": 3, "auth": 4, "admin": 5}


def test_outcome_values_are_stable():
    assert codes.OUTCOME == {"ok": 0, "denied": 1, "error": 2}


def test_target_type_values_are_stable():
    assert codes.TARGET_TYPE == {
        "file": 0, "dir": 1, "role": 2, "acl": 3, "version": 4, "principal": 5}


def test_reverse_maps_round_trip():
    for name, code in codes.CATEGORY.items():
        assert codes.CATEGORY_NAME[code] == name
    for name, code in codes.OUTCOME.items():
        assert codes.OUTCOME_NAME[code] == name
    for name, code in codes.TARGET_TYPE.items():
        assert codes.TARGET_TYPE_NAME[code] == name
