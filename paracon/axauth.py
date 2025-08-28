# =============================================================================
# Copyright (c) 2025-2030 Richard Edmonds
#
# Author: Richard L Edmonds
# License: MIT License
# =============================================================================

"""
axauth module

This module provides classes and functions to construct, disassemble,
compress, and optionally sign or verify Chattervox payloads for use
with ax25 software such as Paracon's pserver.py (AGWPE-based) module.
The implementation isbased on the chattervox protocol v1 from Brannon Dorsey
described at:

https://github.com/brannondorsey/chattervox?tab=readme-ov-file#chattervox-protocol-v1-packet

The Packet class handles the payload-level byte data; AX.25 framing
is handled by the ax.25 software such as Paracon/AGWPE.

Outgoing packets are created with "from_ax25_payload", incoming packets
are created with "to_ax25_payload".

Incoming packets are disassembled, verified, and the sanitised byte payload
and authentication status made available.

Outgoing packets are assembled and signed with the
local private key provided the signing bool is set, and the payload byte array
made available.

Packet authentication status for each incoming packet can be accessed by the calling
program and used as desired such as colouring the displayed text or dropping 
unauthorised commands for example.

"""
import os
import re
import sys
import zlib
from typing import Optional, Tuple
from enum import Enum
import codecs
import configparser
from configparser import ConfigParser
from pathlib import Path
from platformdirs import user_config_dir
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


APP_NAME = "axauth"
CONFIG_FILE = Path(user_config_dir(APP_NAME)) / "config.ini"

def configure(config_path):
    cfg = ConfigParser()

    """Interactive setup: ask for callsign, make config, generate keys."""
    local_call = input("Enter your callsign for authenticating public keys: ").strip().upper()
    if "-" in callsign:
        print("⚠️  Please omit SSID (e.g. use N0CALL instead of N0CALL-1).")
        return
    ssid_input = input("Enter the SSID for your local station (leave blank for 0): ").strip()
    SSID = int(ssid_input) if ssid_input else 0

    # sensible defaults
    private_key_path = config_path.parent / f"{local_call}_private.pem"
    public_keys_dir = config_path.parent / "public_keys"

    cfg["DEFAULT"] = {
        "LOCAL_CALL": local_call,
        "SSID": SSID,
        "private_key": str(private_key_path),
        "public_keys_dir": str(public_keys_dir)
    }

    # write config.ini
    with open(config_path, "w") as f:
        cfg.write(f)

    # ensure directories exist
    public_keys_dir.mkdir(parents=True, exist_ok=True)

    print("Created config.ini at:", config_path)
    print("Private key will be stored at:", private_key_path)
    print("Public keys folder:", public_keys_dir)

    ensure_keys(config_path)


    return cfg

def strip_ssid(call: str) -> str:
    """
    Remove SSID from an AX.25 callsign if present.

    Args:
        call (str): Callsign, possibly with SSID (e.g., 'ZL2DRS-4').

    Returns:
        str: Callsign without SSID (e.g., 'ZL2DRS').
    """
    return call.split("-")[0]


def ensure_config(config_path: Path):
    """Create a config file if it doesn't exist."""
    if not config_path.exists():
        print("Error: No authentication configuration found. Run 'axauth configure'")
        sys.exit(1)

def ensure_keys(config_path: Path):
    # Load config
    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    local_call = cfg["DEFAULT"]["LOCAL_CALL"]
    local_SSID = cfg["DEFAULT"]["SSID"]
    priv_path = Path(cfg["DEFAULT"]["private_key"])
    pub_dir = Path(cfg["DEFAULT"]["public_keys_dir"])
    pub_path = pub_dir / f"{local_call}.pub"

    # Ensure dirs exist
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_dir.mkdir(parents=True, exist_ok=True)

    if priv_path.exists() and pub_path.exists():
        return  # already good

    # Generate keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key
    with priv_path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with pub_path.open("wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"Generated new keypair for {local_call}")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")



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
    INVALID           = "IV"  # Signature invalid (forged/tampered)

# Magic bytes used to identify a Chattervox packet
MAGIC_BYTES = b'\x7a\x39'     #A constant two-byte value used to identify chattervox packets.

version_number = 1           #The protocol version number between 1-255.
version_byte = version_number.to_bytes(1, byteorder='big', signed=False)


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
        self.version_number: Optional[integer]   = version_number
        self.version_byte                        = version_number.to_bytes(1, byteorder='big', signed=False)
        self.signed: Optional[bool]              = False
        self.compressed: Optional[bool]          = False
        self.signature_length: Optional[integer] = 0
        self.signature: Optional[bytes]          = None
        self.message_payload: Optional[bytes]    = None
        self.packet_payload: Optional[bytes]     = None

        #Meta data
        self.from_call: Optional[str]            = None #NEEDS TO BE CALL NOT STATION as it matches a pub key
        self.auth_type: AuthType                 = AuthType.UNKNOWN

        #keys
        self.public_key                          = None
        self.private_key                         = None

        #Load config
        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE)

        # Load keys from config
        self.private_key, self.public_keys_dir = self.load_keys_from_config(self.config)

    def load_keys_from_config(self, config_path: Path):
        """
        Loads the private key and the public keys directory from the config file.
        Returns (private_key_obj, public_keys_dir Path).
        """
        config = self.config

        # Ensure defaults are present
        if "DEFAULT" not in config:
            raise ValueError("Config missing [DEFAULT] section")

        private_key_file = Path(config["DEFAULT"]["PRIVATE_KEY"]).expanduser()
        public_keys_dir  = Path(config["DEFAULT"]["PUBLIC_KEYS_DIR"]).expanduser()

        # --- Load private key ---
        if not private_key_file.exists():
            raise FileNotFoundError(f"Private key file not found: {private_key_file}")

        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        return private_key, public_keys_dir

    def load_public_key(self, from_call):
        """
        Look up and load the public key for self.from_call
        based on the PUBLIC_KEYS_DIR specified in self.config.
        """
        config = self.config
        if from_call is None:
            raise ValueError("from_call is not set")

        # Expand the configured public key directory
        public_keys_dir = Path(self.config["DEFAULT"]["PUBLIC_KEYS_DIR"]).expanduser()

        # Build the expected filename
        key_file = public_keys_dir / f"{self.from_call}.pem"

        if not key_file.exists():
            #raise FileNotFoundError(f"Public key not found for {self.from_call}: {key_file}")
            ############ WE COULD WRITE ALTERNATIVE LOOK UPS HERE ##################
            return None
        else:
            # Load the public key
            with open(key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
        return public_key

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
        header = MAGIC_BYTES  # magic header
        version_byte = self.version_byte

        # --- Flags ---
        # Construct one byte: 6 unused bits, then signature flag, then compression flag
        sig_flag = 1 if self.signed else 0
        comp_flag = 1 if self.compressed else 0
        flags = ((0 << 2) | (sig_flag << 1) | comp_flag)  # put bits in order
        flags_byte = flags.to_bytes(1, "big")

        # --- Signature section ---
        signature_section = b""
        if self.signed:
            if self.private_key:
                self.signature = self.private_key.sign(self.message_payload)
            sig_len = len(self.signature)
            if sig_len > 255:
                raise ValueError("Signature length exceeds 255 bytes.")
            signature_section += sig_len.to_bytes(1, "big")  # length
            signature_section += self.signature             # raw bytes
            self.signature_length = sig_len
            self.auth_type = AuthType.UNTRUSTED
            self._verify_signature(self.from_call)
        else:
            self.auth_type = AuthType.UNSIGNED

        # --- Message section ---
        if self.compressed:
            raise NotImplementedError("Compression not yet implemented.")
        message_section = self.message_payload

        # --- Final assembly ---
        packet_payload = header + version_byte + flags_byte + signature_section + message_section
        self.packet_payload = packet_payload
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

        if not isinstance(packet_payload, (bytes, bytearray)):
            raise TypeError("Data must be bytes or bytearray")

        if len(packet_payload) < 2:
            raise TypeError("Invalid packet: too few bytes")

        self.from_call = from_call

        if packet_payload[:2] != MAGIC_BYTES:
            #This is not a chattervox payload.
            self.packet_payload     = packet_payload
            self.auth_type          = AuthType.UNKNOWN
            return self.packet_payload, self.auth_type
        else:
            # Parse header
            self.version_number = packet_payload[2]
            self.version_byte   = version_number.to_bytes(1, byteorder='big', signed=False)
            flags_byte          = packet_payload[3]
            self.signed         = (flags_byte & 0b10) != 0   # second least significant bit
            self.compressed     = (flags_byte & 0b01) != 0   # least significant bit

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

            # Determine authentication status
            self.auth_type = self._verify_signature(from_call)

        # Return raw payload bytes and authentication status
        return self.message_payload, self.auth_type

    def _verify_signature(self, from_call: Optional[str] = None) -> AuthType:
        """
        Verify the payload signature against the stored public key.

        Args:
            from_call (str, optional): The callsign from AX.25 header.

        Returns:
            AuthType: Authentication status of the payload.
        """

        # No signature present
        if not self.signed or not self.signature:
            return AuthType.UNSIGNED

        # No public key available
        self.public_key = self.load_public_key(from_call)
        if not self.public_key:
            return AuthType.UNTRUSTED

        # Attempt verification
        try:
            self.public_key.verify(self.signature, self.message_pay_load)
            return AuthType.SIGNED_VERIFIED
        except Exception:
            return AuthType.INVALID

    def _callsign_matches_key(self, call: str, pubkey) -> bool:
        """
        Placeholder for mapping check between callsign and public key.
        Replace with your real trust model or directory lookup.
        """
        return True  # for now, accept everything


def to_ax25_payload(from_call: str,
                    message_payload: bytes,
                    sign: bool = False
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
    pkt.from_call = strip_ssid(from_call)
    pkt.message_payload = message_payload
    pkt.signed = sign
    if pkt.signed:
        pkt.load_keys_from_config(pkt.config)
        pkt.signature = pkt.private_key.sign(pkt.message_payload)
    else:
        pkt.signature = None

    pkt.assemble(sign=sign)
    return pkt

def from_ax25_payload(packet_payload: bytes,
                       from_call: Optional[str] = None,
                       public_key: Optional[str] = None
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
    if public_key:
        pkt.public_key = public_key
    pkt.disassemble(packet_payload, from_call=strip_ssid(from_call))
    return pkt

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "configure":
        configure(CONFIG_FILE)
    else:
        print("Usage: python3 axauth.py configure")


if __name__ == "__main__":
    main()
