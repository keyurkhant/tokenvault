from __future__ import annotations

from tokenvault.fields.base import FieldType, PIIField


def test_field_type_values():
    assert FieldType.EMAIL == "email"
    assert FieldType.NAME == "name"
    assert FieldType.PHONE == "phone"
    assert FieldType.ADDRESS == "address"
    assert FieldType.DATE_OF_BIRTH == "date_of_birth"
    assert FieldType.NATIONAL_ID == "national_id"
    assert FieldType.CUSTOM == "custom"


def test_pii_field_repr_hides_value():
    f = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    r = repr(f)
    assert "jane@example.com" not in r
    assert "[REDACTED]" in r


def test_pii_field_is_frozen():
    f = PIIField(name="email", field_type=FieldType.EMAIL, value="x")
    try:
        f.value = "y"  # type: ignore
        assert False
    except Exception:
        pass


def test_field_type_from_string():
    ft = FieldType("email")
    assert ft is FieldType.EMAIL
