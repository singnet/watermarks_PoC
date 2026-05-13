"""CRC helpers for watermark payload error detection.

A watermark extractor operates on a noisy channel.  Error-correcting codes try
to recover the intended bitstream, but the verifier still needs a cheap way to
reject a corrupted payload before it is interpreted as a manifest locator.  The
Step 12 reference implementation uses CRC-16/CCITT-FALSE for this purpose.

CRC is **not cryptographic**.  It does not authenticate the payload and it does
not prevent malicious modification.  OProW's security comes later from locator
self-consistency, signed manifests, essence matching, and trust policy.  CRC is
only an engineering checksum that catches accidental extraction errors.
"""

from __future__ import annotations


def crc16_ccitt_false(data: bytes) -> int:
    """Compute CRC-16/CCITT-FALSE over ``data``.

    Parameters match the common CCITT-FALSE variant:

    * width: 16 bits
    * polynomial: 0x1021
    * initial value: 0xFFFF
    * input reflected: false
    * output reflected: false
    * xor out: 0x0000
    """

    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF
