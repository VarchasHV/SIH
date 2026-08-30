"""
PyTest Suite for Tier1_FastPath & Hybrid Routing Architecture.
Tests edge cases for Aadhaar, Phone (IN), SSN, IPv4, and Two-Tier payload routing.
"""

import sys
from pathlib import Path

# Add project root and server directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

import pytest
from tier1_fastpath import (
    Tier1_FastPath,
    verhoeff_valid,
    luhn_valid,
    analyzePayload,
)


# -----------------------------------------------------------------------------
# FIX 1: Aadhaar Validation (Dashes, Spaces, Unspaced, Verhoeff Checksum)
# -----------------------------------------------------------------------------

def test_aadhaar_spaced_valid():
    text = "My Aadhaar number is 2345 6789 0124 for e-KYC."
    hits = Tier1_FastPath.detect(text)
    assert any(h["category"] == "aadhaar" and "2345 6789 0124" in h["value"] for h in hits)


def test_aadhaar_unspaced_valid():
    text = "Submit UID 234567890124 to continue."
    hits = Tier1_FastPath.detect(text)
    assert any(h["category"] == "aadhaar" and h["value"] == "234567890124" for h in hits)


def test_aadhaar_dash_separated_valid():
    text = "Aadhaar with dashes: 2345-6789-0124 on document."
    hits = Tier1_FastPath.detect(text)
    assert any(h["category"] == "aadhaar" and h["value"] == "2345-6789-0124" for h in hits)


def test_aadhaar_invalid_verhoeff_rejected():
    text = "Invalid number 234567890123 should not be detected as Aadhaar."
    hits = Tier1_FastPath.detect(text)
    assert not any(h["category"] == "aadhaar" for h in hits)


# -----------------------------------------------------------------------------
# FIX 2: Phone (IN) Boundary & Timestamp Negative Gating
# -----------------------------------------------------------------------------

def test_phone_valid_formats():
    samples = [
        "Call me at +91 9876543210 today",
        "Mobile: 9876543210 on record",
        "Contact +91-9876543210 for support",
    ]
    for text in samples:
        hits = Tier1_FastPath.detect(text)
        assert any(h["category"] == "phone-in" for h in hits), f"Failed for {text}"


def test_phone_inside_epoch_timestamp_rejected():
    text = "Server event occurred at timestamp 1698765432100 in production."
    hits = Tier1_FastPath.detect(text)
    assert not any(h["category"] == "phone-in" for h in hits)


def test_phone_non_indian_start_digit_rejected():
    text = "Reference code 1234567890 is not an Indian mobile."
    hits = Tier1_FastPath.detect(text)
    assert not any(h["category"] == "phone-in" for h in hits)


# -----------------------------------------------------------------------------
# FIX 3: SSN Negative Lookbehind Gating
# -----------------------------------------------------------------------------

def test_ssn_valid_standalone():
    text = "Social Security number is 123-45-6789 on the W-9 form."
    hits = Tier1_FastPath.detect(text)
    assert any(h["category"] == "ssn" and h["value"] == "123-45-6789" for h in hits)


@pytest.mark.parametrize("prefix", [
    "Order: ",
    "Order-",
    "order ",
    "Ref: ",
    "ref-",
    "ID: ",
    "id-",
    "Batch: ",
    "Serial-",
    "Part: ",
])
def test_ssn_with_ignorable_id_prefixes_rejected(prefix):
    text = f"The item identifier is {prefix}123-45-6789 in catalog."
    hits = Tier1_FastPath.detect(text)
    assert not any(h["category"] == "ssn" for h in hits), f"False positive for prefix {prefix}"


# -----------------------------------------------------------------------------
# FIX 4: IPv4 Negative Lookbehind Gating for Software Versions
# -----------------------------------------------------------------------------

def test_ipv4_valid_address():
    text = "Connecting to host 192.168.1.42 on port 8080."
    hits = Tier1_FastPath.detect(text)
    assert any(h["category"] == "ipv4" and h["value"] == "192.168.1.42" for h in hits)


@pytest.mark.parametrize("ver_str", [
    "v1.2.3.4",
    "V1.2.3.4",
    "version 1.2.3.4",
    "Version 1.2.3.4",
    "v. 1.2.3.4",
    "Version. 2.10.0.1",
])
def test_ipv4_software_version_rejected(ver_str):
    text = f"Release {ver_str} deployed to production cluster."
    hits = Tier1_FastPath.detect(text)
    assert not any(h["category"] == "ipv4" for h in hits), f"False positive for {ver_str}"


# -----------------------------------------------------------------------------
# Two-Tier Router & Performance Constraints
# -----------------------------------------------------------------------------

def test_router_text_payload_sub10ms():
    payload = {
        "type": "text",
        "text": "Please verify user with Aadhaar 2345-6789-0124 and email test@example.com.",
    }
    res = analyzePayload(payload)
    assert res["tier"] == 1
    assert res["sub10ms"] is True
    assert res["latencyMs"] < 10.0
    cats = [d["category"] for d in res["detections"]]
    assert "aadhaar" in cats
    assert "email" in cats


def test_router_image_payload_routes_to_tier2():
    payload = {
        "type": "image",
        "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    }
    res = analyzePayload(payload)
    assert res["tier"] == 2
    assert "results" in res
