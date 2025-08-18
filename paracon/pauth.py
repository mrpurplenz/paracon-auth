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
        from_call (str): Sender callsign (from AX.25 header).
        byte_message (bytes): Byte message for the payload.
        signature (bytes): Digital signature.
        data (bytes): Assembled payload ready for AGWPE transmission.
        auth_type (AuthType): Authentication status after verification.
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
        version = self.version.to_bytes(1, "big")
    
        # --- Flags ---
        # Construct one byte: 6 unused bits, then signature flag, then compression flag
        sig_flag = 1 if self.signature else 0
        comp_flag = 1 if self.compressed else 0
        flags = ((0 << 2) | (sig_flag << 1) | comp_flag)  # put bits in order
        flags_byte = flags.to_bytes(1, "big")
    
        # --- Signature section ---
        signature_section = b""
        if self.signature:
            sig_len = len(self.signature)
            if sig_len > 255:
                raise ValueError("Signature length exceeds 255 bytes.")
            signature_section += sig_len.to_bytes(1, "big")  # length
            signature_section += self.signature             # raw bytes
    
        # --- Message section ---
        if self.compressed:
            raise NotImplementedError("Compression not yet implemented.")

    
        message_section = self.byte_message

        # Final payload
        self.data = header + version + flags_byte + signature_section + message_section
        return self.data
        
    def disassemble(self, packet_payload: bytes, sender_call: Optional[str] = None) -> Tuple[bytes, AuthType]:
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
        if not isinstance(packet_payload, (bytes, bytearray)):
            raise TypeError("Data must be bytes or bytearray")
    
        if len(packet_payload) < 2:
            raise TypeError("Invalid packet: too few bytes")
    
        if data[:2] != MAGIC_BYTES:
            #This is not a chattervox payload.
            self.from_call          = sender_call
            self.packet_payload     = packet_payload
            self.auth_type          = AuthType.UNKNOWN
            return self.packet_payload, self.auth_type
        else:
        
            # Parse header
            self.version = int.from_bytes(packet_payload[2], "big")
            flags = data[3]
            self.compressed = int.from_bytes(packet_payload[3], "big")>2
            self.signed     = mod(int.from_bytes(packet_payload[3], "big"),2)>0
        
            idx = 4
            if self.signed:
                self.signature_length = int.from_bytes(packet_payload[4], "big")
                self.signature = packet_payload[5:5 + sig_len]
                idx = 5 + sig_len
            else:
                self.signature = None
                self.header['signature_length'] = 0
        
            # Slice the remaining payload (message/compressed data)
            message_payload = packet_payload[idx:]
            self.message_payload = message_payload  # keep raw bytes for further processing
        
            # Determine authentication type without decoding the message
            self.auth_type = self._verify_signature(sender_call)
        
        # Return raw payload bytes and AuthType
        return self.message_payload, self.auth_type

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

def to_ax25_payload(from_call: str, 
                    byte_message: bytes,
                    to_call: Optional[str],
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
    pkt.from_station = from_call
    pkt.to_station = to_call
    pkt.message = message
    if signature:
        pkt.signature = signature
    pkt.assemble(sign=sign)
    return pkt

def from_ax25_payload(packet_payload: bytes, sender_call: Optional[str] = None) -> Packet:
    """
    Parse bytes received from AX.25 into a Packet object with AuthType.

    Args:
        packet_payload (bytes): Payload from AX.25 frame.
        sender_call (str, optional): AX.25 source callsign (excluding SSID).

    Returns:
        Packet: Parsed Packet object with auth_type set.
    """
    pkt = Packet()
    pkt.disassemble(packet_payload, sender_call=sender_call)
    return pkt

