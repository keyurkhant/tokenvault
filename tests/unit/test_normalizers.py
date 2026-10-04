import pytest
from hypothesis import given, strategies as st

from tokenvault.fields.email import EmailNormalizer
from tokenvault.fields.name import NameNormalizer
from tokenvault.fields.phone import PhoneNormalizer
from tokenvault.fields.dob import DateOfBirthNormalizer
from tokenvault.fields.address import AddressNormalizer
from tokenvault.fields.national_id import NationalIDNormalizer
from tokenvault.fields.custom import PassthroughNormalizer


# --- Email ---
def test_email_lowercase():
    assert EmailNormalizer().normalize("Jane@Example.COM") == "jane@example.com"

def test_email_strips_subaddress():
    assert EmailNormalizer().normalize("jane+promo@example.com") == "jane@example.com"

def test_email_strips_whitespace():
    assert EmailNormalizer().normalize("  jane @example.com  ") == "jane@example.com"

def test_email_empty():
    assert EmailNormalizer().normalize("") == ""

@given(st.emails())
def test_email_idempotent(email: str):
    n = EmailNormalizer()
    once = n.normalize(email)
    assert n.normalize(once) == once


# --- Name ---
def test_name_lowercase_strip():
    assert NameNormalizer().normalize("  JANE  SMITH  ") == "jane smith"

def test_name_removes_punctuation():
    assert NameNormalizer().normalize("O'Brien") == "obrien"

def test_name_empty():
    assert NameNormalizer().normalize("") == ""

@given(st.text(min_size=0, max_size=50))
def test_name_idempotent(s: str):
    n = NameNormalizer()
    once = n.normalize(s)
    assert n.normalize(once) == once


# --- Phone ---
def test_phone_strips_formatting():
    assert PhoneNormalizer().normalize("(416) 555-1234") == "+4165551234"

def test_phone_keeps_plus():
    assert PhoneNormalizer().normalize("+14165551234") == "+14165551234"

def test_phone_empty():
    assert PhoneNormalizer().normalize("") == "+"


# --- DOB ---
def test_dob_iso_passthrough():
    assert DateOfBirthNormalizer().normalize("1990-05-21") == "1990-05-21"

def test_dob_slash_ddmmyyyy():
    assert DateOfBirthNormalizer().normalize("21/05/1990") == "1990-05-21"


# --- Address ---
def test_address_lowercase():
    assert AddressNormalizer().normalize("123 Main St") == "123 main st"

def test_address_collapses_spaces():
    assert AddressNormalizer().normalize("123  Main   St") == "123 main st"


# --- National ID ---
def test_national_id_strips_separators():
    assert NationalIDNormalizer().normalize("123-456-789") == "123456789"

def test_national_id_uppercase():
    assert NationalIDNormalizer().normalize("ab 12 cd") == "AB12CD"


# --- Passthrough ---
def test_passthrough_strips():
    assert PassthroughNormalizer().normalize("  hello  ") == "hello"
