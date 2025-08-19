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

Outgoing packets are created with "from_ax25_payload", incoming packets
are created with "to_ax25_payload".

Incoming packets are disassembled, verified, and the sanitised byte payload
and authentication status made available. 

Outgoing packets are assembled and signed with the 
local private key provided the signing bool is set, and the payload byte array
made available.

Packet authentication status for each incoming packet can be accessed by the calling
pserver and passed as desired to the tui layer to be handled as desired by way of text colour
in the terminal for example.

"""

import zlib
from typing import Optional, Tuple
from enum import Enum
import codecs
def bprint(data):
     print(codecs.encode(data, "hex").decode())

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
MAGIC_BYTES = b'\x7a\x39'     #A constant two-byte value used to identify chattervox packets.
VERSION = b'\x01'             #A protocol version number between 1-255.

class HeaderFlags:
    """Bitmask flags for Chattervox packet headers."""
    SIGNED            = False  #A value of True indicates that the message contains a ECDSA digital signature.    
    COMPRESSED        = False  #A value of True indicates that the message payload is compressed.

class Packet:
    """
    Represents a Chattervox packet payload.

    Attributes:
        #Packet data
        version (integer): Version number (1 to 255) 
        signed (bool): Message is signed
        compressed (bool): Message is compressed
        signature_length (integer):  Length of signature
        signature (bytes): Digital signature
        message_payload (bytes): byte form of message only
        packet_payload (bytes): Payload ready to send over AGWPE

        #Meta data
        from_call (string): packet sender callsign (excluding SSID)
        auth_type (AuthType): Enum of authentication status

    """

    def __init__(self):
        #Packet data
        self.version: Optional[integer]          = 0  
        self.signed: Optional[bool]              = False
        self.compressed: Optional[bool]          = False
        self.signature_length: Optional[integer] = 0
        self.signature: Optional[bytes]          = None
        self.message_payload: Optional[bytes]    = None
        self.packet_payload: Optional[bytes]     = None

        #Meta data
        self.from_call: Optional[str]            = None
        self.auth_type: AuthType                 = AuthType.UNKNOWN

        #keys
        self.public_key                          = None
        self.private_key                         = None

    def assemble(self, sign: bool = False) -> bytes:
        """
        Assemble the packet payload into bytes for AX.25 transmission.

        Args:
            sign (bool): If True, generate a signature using local private key.

        Returns:
            bytes: Complete payload including header, optional signature, and message.

        Payload layout:
            - [0x0000] 16 bits  Magic Header b'x7a39'
            - [0x0002] 8 bits   Version Byte b'x01'
            - [0x0003] 6 bits   Reserved/Unused
            - [0x0003] 1 bit    Digital Signature Flag
            - [0x0003] 1 bit    Compression Flag
            - [0x0004] [opt] 8 bits Signature Length
            - [0x0005] [opt] Signature (Signature Length bytes)
            - [rest]   Message (raw or compressed bytes)

        """
        payload = b''

        # --- Fixed header ---
        header = b"\x7a\x39"  # magic header
        #bprint(header)
        version = self.version.to_bytes(1, "big")

        # --- Flags ---
        # Construct one byte: 6 unused bits, then signature flag, then compression flag
        sig_flag = 1 if self.signature else 0
        comp_flag = 1 if self.compressed else 0
        flags = ((0 << 2) | (sig_flag << 1) | comp_flag)  # put bits in order
        flags_byte = flags.to_bytes(1, "big")

        # --- Signature section ---
        signature_section = b""
        if self.signed:
            #We actually need to obtain a private key at this point then ceate the message signature


            sig_len = len(self.signature)
            if sig_len > 255:
                raise ValueError("Signature length exceeds 255 bytes.")
            signature_section += sig_len.to_bytes(1, "big")  # length
            signature_section += self.signature             # raw bytes
        else:
            self.auth_type = AuthType.UNSIGNED

        # --- Message section ---
        if self.compressed:
            raise NotImplementedError("Compression not yet implemented.")


        message_section = self.message_payload

        # Final payload
        packet_payload = header + version + flags_byte + signature_section + message_section
        self.packet_payload = packet_payload
        #print("assembled packet_payload")
        #bprint(packet_payload)
        return self.packet_payload

    def disassemble(self, packet_payload: bytes, from_call: Optional[str] = None) -> Tuple[bytes, AuthType]:
        """
        Parse incoming packet payload bytes, populate the packet data
        and determine authentication status. Does not decode message content.

        Args:
            packet_payload (bytes): Raw payload from AX.25 frame.
            sender_call (str, optional): AX.25 source callsign for signature verification.

        Returns:
            Tuple[bytes, AuthType]: Sanitized payload bytes and authentication status.

        Raises:
            TypeError: If the packet is invalid or too short.
        """
        #print("unpacking the following payload")
        #bprint(packet_payload)

        if not isinstance(packet_payload, (bytes, bytearray)):
            raise TypeError("Data must be bytes or bytearray")

        if len(packet_payload) < 2:
            raise TypeError("Invalid packet: too few bytes")

        self.from_call = from_call

        if packet_payload[:2] != MAGIC_BYTES:
            #This is not a chattervox payload.
            #print("not CV packet")
            self.packet_payload     = packet_payload
            self.auth_type          = AuthType.UNKNOWN
            return self.packet_payload, self.auth_type
        else:
            # Parse header
            self.version    = packet_payload[2]
            flags_byte      = packet_payload[3]
            self.signed     = (flags_byte & 0b10) != 0   # second least significant bit
            self.compressed = (flags_byte & 0b01) != 0   # least significant bit

            idx = 4
            if self.signed:
                self.signature_length = packet_payload[4]
                self.signature = packet_payload[5:5 + self.signature_length]
                idx = 5 + self.signature_length
            else:
                self.signature = None
                self.signature_length = 0

            # Slice the remaining payload (message/compressed data)
            message_payload = packet_payload[idx:]
            self.message_payload = message_payload  # keep raw bytes for further processing
            self.packet_payload = packet_payload
            # Determine authentication type without decoding the message
            self.auth_type = self._verify_signature(from_call)

        # Return raw payload bytes and AuthType
        return self.message_payload, self.auth_type

    def _verify_signature(self, from_call: Optional[str] = None) -> AuthType:
        """
        Placeholder function to determine authentication status.

        Args:
            from_call (str): The callsign from AX.25 header.

        Returns:
            AuthType: Authentication status of the payload.
        """
        if not self.signed:
            return AuthType.UNSIGNED
        if from_call is None:
            return AuthType.UNTRUSTED

        public_key

        # Here insert real signature verification against public keyring
        # Example placeholder logic:
        # if signature valid and public key found:
        #     return AuthType.SIGNED_VERIFIED
        # if signature present but key missing:
        #     return AuthType.UNTRUSTED
        # if signature invalid:
        #     return AuthType.INVALID

        return AuthType.SIGNED_VERIFIED  # default placeholder

def to_ax25_payload(from_call: str,
                    message_payload: bytes,
                    sign: bool = False,
                    signature: Optional[bytes] = None
                   ) -> Packet:
    """
    Create a Packet object and assemble it into bytes.

    Args:
        message (bytes): a byte array message ready to send via AWGPE.
        from_call (str): Sender callsign (Doesnt include SSID), used to id the public key
        signature (bytes, optional): Signature bytes.
        sign (bool): Whether to sign the message.

    Returns:
        Packet: Assembled Packet object ready for AX.25 transmission.
    """
    pkt = Packet()
    pkt.from_call = from_call
    pkt.message_payload = message_payload
    pkt.signed = sign
    if pkt.signed:
        pkt.signature = signature
    else:
        pkt.signature = None
    pkt.assemble(sign=sign)
    return pkt

def from_ax25_payload(packet_payload: bytes,
                       from_call: Optional[str] = None
                     ) -> Packet:
    """
    Parse bytes received from AX.25 into a Packet object with AuthType.

    Args:
        packet_payload (bytes): Payload from AX.25 frame.
        sender_call (str, optional): AX.25 source callsign (excluding SSID).

    Returns:
        Packet: Parsed Packet object with auth_type set.
    """
    pkt = Packet()
    pkt.disassemble(packet_payload, from_call=from_call)
    return pkt

