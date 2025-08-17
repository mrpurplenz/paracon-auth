# =============================================================================
# Copyright (c) 2025-2030 Richard Edmonds
#
# Author: Richard L Edmonds
# License: MIT License
# =============================================================================

"""
Paracon Auth module

This module provides classes and functions to construct, disassemble,
compress, and optionally sign or verify Chattervox payloads for use
with Paracon's pserver.py (AGWPE-based) module. The implementation is
based on the chattervox protocol v1 from Brannon Dorsey described at
https://github.com/brannondorsey/chattervox?tab=readme-ov-file#chattervox-protocol-v1-packet

The Packet class handles the payload-level byte data; AX.25 framing
is handled by Paracon/AGWPE.

PAcket authentication status will be passed by Enum back through
the pserver to the tui to allow for a differentiated display by way of text colour
in the terminal.

"""

import zlib
from typing import Optional
from enum import Enum


class AuthType(Enum):
    """
    Type used to identify the authentication status for display in 
    Paracon.
    """
    UNKNOWN           = "UK"  # Unknown or not yet determined
    UNSIGNED          = "NS"  # No signature present
    SIGNED_VERIFIED   = "SV"  # Signature present and verified
    UNTRUSTED         = "UT"  # Signature present but no public key available
    SIGNED_MISMATCH   = "SM"  # Sender call, sig call missmatch
    INVALID           = "IV"  # Signature invalid (forged/tampered)

# Magic bytes used to identify a Chattervox packet
MAGIC_BYTES = bytes([0x7A, 0x39])
VERSION = 0x01

class HeaderFlags:
    """Bitmask flags for Chattervox packet headers."""
    COMPRESSED = 0x01
    SIGNED = 0x02

class Packet:
    """
    Represents a Chattervox packet payload.

    Attributes:
        from_station (str): Sender callsign (from AX.25 header).
        to_station (str): Recipient callsign.
        message (str): UTF-8 message payload.
        signature (bytes): Optional digital signature.
        data (bytes): Assembled payload ready for AX.25 transmission.
        auth_type (AuthType): Authentication status after verification.
    """

    def __init__(self):
        self.from_station: Optional[str] = None
        self.to_station: Optional[str] = None
        self.message: Optional[str] = None
        self.signature: Optional[bytes] = None
        self.data: Optional[bytes] = None
        self.header = {
            'version': VERSION,
            'compressed': None,
            'signed': None,
            'signature_length': None
        }
        self.auth_type: AuthType = AuthType.UNKNOWN

    def assemble(self, sign: bool = False) -> bytes:
        """
        Assemble the packet payload into bytes for AX.25 transmission.

        Args:
            sign (bool): If True, generate a signature using local private key.

        Returns:
            bytes: Complete payload including header, optional signature, and message.
        """
        payload = b''

        # Placeholder: signature logic
        if sign and self.signature:
            self.header['signed'] = True
            self.header['signature_length'] = len(self.signature)
            payload += self.signature
        else:
            self.header['signed'] = False
            self.header['signature_length'] = 0

        # Encode message to bytes
        message_bytes = self.message.encode('utf-8')
        compressed_bytes = zlib.compress(message_bytes)
        if len(compressed_bytes) < len(message_bytes):
            self.header['compressed'] = True
            payload += compressed_bytes
        else:
            self.header['compressed'] = False
            payload += message_bytes

        # Build header flags
        flags = 0x00
        if self.header['signed']:
            flags |= HeaderFlags.SIGNED
        if self.header['compressed']:
            flags |= HeaderFlags.COMPRESSED

        # Construct header bytes
        header_bytes = bytearray(MAGIC_BYTES)
        header_bytes.append(self.header['version'])
        header_bytes.append(flags)
        if self.header['signed']:
            header_bytes.append(self.header['signature_length'])

        # Final payload
        self.data = bytes(header_bytes) + payload
        return self.data

    def disassemble(self, data: bytes, sender_call: Optional[str] = None):
        """
        Parse incoming Chattervox payload bytes and determine authentication status.

        Args:
            data (bytes): Payload from AX.25 frame.
            sender_call (str): AX.25 source callsign for signature verification.

        Raises:
            TypeError: If packet is invalid.
        """
        if len(data) < 4:
            raise TypeError("Invalid packet: too few bytes")
        if data[:2] != MAGIC_BYTES:
            raise TypeError("Invalid packet: bad magic bytes")

        # Header
        self.header['version'] = data[2]
        flags = data[3]
        self.header['compressed'] = bool(flags & HeaderFlags.COMPRESSED)
        self.header['signed'] = bool(flags & HeaderFlags.SIGNED)

        idx = 4
        if self.header['signed']:
            self.header['signature_length'] = data[4]
            self.signature = data[5:5 + self.header['signature_length']]
            idx = 5 + self.header['signature_length']
        else:
            self.signature = None

        payload = data[idx:]
        if self.header['compressed']:
            self.message = zlib.decompress(payload).decode('utf-8')
        else:
            self.message = payload.decode('utf-8')

        # Determine AuthType using sender_call and available signature
        self.auth_type = self._verify_signature(sender_call)

    def _verify_signature(self, sender_call: Optional[str] = None) -> AuthType:
        """
        Placeholder function to determine authentication status.

        Args:
            sender_call (str): The callsign from AX.25 header.

        Returns:
            AuthType: Authentication status of the payload.
        """
        if not self.signature:
            return AuthType.UNSIGNED
        if sender_call is None:
            return AuthType.UNTRUSTED

        # Here insert real signature verification against public keyring
        # Example placeholder logic:
        # if signature valid and public key found:
        #     return AuthType.SIGNED_VERIFIED
        # if signature present but key missing:
        #     return AuthType.UNTRUSTED
        # if signature invalid:
        #     return AuthType.INVALID

        return AuthType.SIGNED_VERIFIED  # default placeholder

def to_ax25_payload(message: str, from_call: str, to_call: str,
                    signature: Optional[bytes] = None,
                    sign: bool = False) -> Packet:
    """
    Create a Packet object and assemble it into bytes.

    Args:
        message (str): UTF-8 message to send.
        from_call (str): Sender callsign.
        to_call (str): Recipient callsign.
        signature (bytes, optional): Signature bytes.
        sign (bool): Whether to sign the message.

    Returns:
        Packet: Assembled Packet object ready for AX.25 transmission.
    """
    pkt = Packet()
    pkt.from_station = from_call
    pkt.to_station = to_call
    pkt.message = message
    if signature:
        pkt.signature = signature
    pkt.assemble(sign=sign)
    return pkt

def from_ax25_payload(payload: bytes, sender_call: Optional[str] = None) -> Packet:
    """
    Parse bytes received from AX.25 into a Packet object with AuthType.

    Args:
        payload (bytes): Payload from AX.25 frame.
        sender_call (str, optional): AX.25 source callsign for verification.

    Returns:
        Packet: Parsed Packet object with auth_type set.
    """
    pkt = Packet()
    pkt.disassemble(payload, sender_call=sender_call)
    return pkt

