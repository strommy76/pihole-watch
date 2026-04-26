"""DGA classifier tests -- legitimate, suspicious, allowlist, and edge cases."""

from __future__ import annotations

from pihole_watch.dga import dga_score, domain_features


# --- legit domains stay below the 0.65 flag threshold ---------------------


def test_google_below_threshold() -> None:
    assert dga_score("google.com") < 0.30


def test_api_stripe_low() -> None:
    assert dga_score("api.stripe.com") < 0.30


def test_amazon_low() -> None:
    assert dga_score("amazon.com") < 0.30


def test_safebrowsing_below_threshold() -> None:
    # Real english-ish "safebrowsing" -- should not flag.
    assert dga_score("safebrowsing.googleapis.com") < 0.30


def test_cloudflare_below_threshold() -> None:
    assert dga_score("cloudflare.com") < 0.30


def test_short_label_not_flagged() -> None:
    assert dga_score("www.youtube.com") < 0.30
    assert dga_score("mail.google.com") < 0.30


# --- DGA-like labels score above 0.65 -------------------------------------


def test_random_letters_only_high() -> None:
    assert dga_score("xkqzlpwjbxqfzgvr.com") > 0.65


def test_letters_with_digits_high() -> None:
    assert dga_score("xnvbq3mlpoq.evil.com") > 0.65


def test_mixed_alphanumeric_high() -> None:
    assert dga_score("d3jk89s7s5slkj.com") > 0.65


def test_alternating_letter_digit_high() -> None:
    # q1w2e3r4t5y6u7 -- heavy digit content even though entropy alone is OK
    assert dga_score("q1w2e3r4t5y6u7.example.com") > 0.65


def test_long_random_label_high() -> None:
    assert dga_score("vu1q3kpalsj9pdqvopzmnj.evil.org") > 0.65


# --- allowlist short-circuits to 0.0 --------------------------------------


def test_cloudfront_is_allowlisted() -> None:
    assert dga_score("d111111abcdef8.cloudfront.net") == 0.0


def test_amazonaws_is_allowlisted() -> None:
    assert dga_score("ec2-203-0-113-25.us-west-2.compute.amazonaws.com") == 0.0


def test_akamai_is_allowlisted() -> None:
    assert dga_score("a1b2c3.akamai.net") == 0.0


def test_googleusercontent_is_allowlisted() -> None:
    assert dga_score("lh3.googleusercontent.com") == 0.0


# --- features ------------------------------------------------------------


def test_features_keys_present() -> None:
    f = domain_features("example.com")
    assert {"length", "entropy", "vowel_ratio", "max_consonant_run",
            "digit_ratio", "distinct_char_ratio"} <= set(f.keys())


def test_features_empty_domain() -> None:
    f = domain_features("")
    assert f["length"] == 0.0
    assert f["entropy"] == 0.0


def test_features_strip_uk_suffix() -> None:
    # Multi-part suffix .co.uk -- registrable label is leftmost ("foo")
    f = domain_features("foo.bar.co.uk")
    assert f["length"] == 3.0


def test_score_is_clamped_to_unit_interval() -> None:
    # Even maximally suspicious input should not exceed 1.0
    assert 0.0 <= dga_score("zzqqxxvvbbnnmmzzqqxxvv9z.evil.com") <= 1.0
