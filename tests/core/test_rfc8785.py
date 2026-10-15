"""RFC 8785 reference vectors (Appendix B number serialisation and the section 3.2 examples)."""

import json
import struct

import pytest

from tripline_scope.core.canonical import canonical_bytes

NUMBERS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("hexbits,expected", NUMBERS)
def test_number_vectors(hexbits, expected):
    value = struct.unpack(">d", bytes.fromhex(hexbits))[0]
    assert canonical_bytes(value).decode() == expected


@pytest.mark.parametrize("hexbits", ["7fffffffffffffff", "7ff0000000000000"])
def test_nan_and_infinity_rejected(hexbits):
    value = struct.unpack(">d", bytes.fromhex(hexbits))[0]
    with pytest.raises(Exception):
        canonical_bytes(value)


def test_section_3_2_2_example():
    bs = chr(92)  # backslash; built programmatically so no tool or editor reinterprets the escapes
    string_json = (bs + "u20ac$" + bs + "u000F" + bs + "u000aA'" + bs + "u0042" + bs + "u0022" + bs + "u005c"
                   + bs + bs + bs + '"' + bs + "/")
    src = ('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "'
           + string_json + '", "literals": [null, true, false]}')
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"'
                + chr(0x20AC) + "$" + bs + "u000f" + bs + "nA'B" + bs + '"' + bs * 4 + bs + '"/"}')
    assert canonical_bytes(json.loads(src)).decode("utf-8") == expected


def test_section_3_2_3_key_sorting_by_utf16():
    src = {
        chr(0x20AC): "Euro Sign",
        chr(13): "Carriage Return",
        chr(0xFB33): "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        chr(0x1F600): "Emoji: Grinning Face",
        chr(0x80): "Control",
        chr(0xF6): "Latin Small Letter O With Diaeresis",
    }
    out = json.loads(canonical_bytes(src))
    assert list(out.values()) == ["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis",
                                  "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]
