# paracon/test_pauth.py

import unittest
import nacl
from nacl.signing import SigningKey
import pauth
import codecs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import configparser
from configparser import ConfigParser
from pathlib import Path
from platformdirs import user_config_dir

APP_NAME = "axauth"
CONFIG_FILE = Path(user_config_dir(APP_NAME)) / "config.ini"

def dep_make_test_keypair():
    """
    Generate a new Ed25519 keypair (private + public).
    Returns (private_key, public_key_bytes).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PublicFormat.Raw
    )
    return private_key, public_bytes


def bprint(data):
    print(codecs.encode(data, "hex").decode())

class TestPauthRoundTrip(unittest.TestCase):

    def setUp(self):
        #read in current config and store
        config_path = CONFIG_FILE
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        #We will test with our own call as the from call
        self.local_call = self.config["DEFAULT"]["LOCAL_CALL"]
        self.from_call = self.local_call
        #self.local_SSID = Path(self.config["DEFAULT"]["LOCAL_SSID"])
        #self.local_station = self.from_call + "-" + self.local_SSID
        self.private_key_file = Path(self.config["DEFAULT"]["PRIVATE_KEY"])
        public_keys_dir = Path(self.config["DEFAULT"]["PUBLIC_KEYS_DIR"])
        
        # --- Load private key ---
        if not self.private_key_file.exists():
            raise FileNotFoundError(f"Private key file not found: {private_key_file}")

        with open(self.private_key_file, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )        

        # Generate an ephemeral keypair (Chattervox style)
        #self.signing_key = SigningKey.generate()
        #self.verify_key = self.signing_key.verify_key
        #self.from_station = "N0CALL-4"
        self.message_payload = b"Hello AX.25!"
        #priv, pub = make_test_keypair()
        #self.private_key = priv
        #self.public_key = pub



    def test_roundtrip_unsigned(self):
        """Round trip without signing"""
        pkt_out = pauth.to_ax25_payload(
            from_call=self.local_call,
            message_payload=self.message_payload,
            sign=False
        )

        # Parse back
        raw_bytes = pkt_out.packet_payload
        self.assertEqual(False,pkt_out.signed)
        self.assertEqual(self.local_call, pkt_out.from_call)
        self.assertEqual(self.message_payload, pkt_out.message_payload)
        self.assertEqual(None, pkt_out.signature)

    def test_roundtrip_signed(self):
        """Round trip with signature"""
        # Sign the message manually
        #signature = self.private_key.sign(self.message_payload)
        #signature = self.signing_key.sign(self.message_payload).signature
        #self.signature = signature
        pkt_out = pauth.to_ax25_payload(
            from_call=self.from_call,
            message_payload=self.message_payload,
            sign=True
        )

        self.assertEqual(True,pkt_out.signed)
        self.assertEqual(self.from_call, pkt_out.from_call)
        self.assertEqual(self.message_payload, pkt_out.message_payload)

    def test_double_roundtrip_unsigned(self):
        """Round trip without signing"""
        pkt_out = pauth.to_ax25_payload(
            from_call=self.from_call,
            message_payload=self.message_payload,
            sign=False
        )

        # Parse back
        raw_bytes = pkt_out.packet_payload
        self.assertEqual(False,pkt_out.signed)
        self.assertEqual(self.from_call, pkt_out.from_call)
        self.assertEqual(self.message_payload, pkt_out.message_payload)
        self.assertEqual(None, pkt_out.signature)
        #print("part one bytes")
        #bprint(raw_bytes)

        double_pkt_out = pauth.from_ax25_payload(
            from_call=pkt_out.from_call,
            packet_payload=pkt_out.packet_payload
        )
        self.assertEqual(pkt_out.version, double_pkt_out.version)
        self.assertEqual(pkt_out.signed, double_pkt_out.signed)
        self.assertEqual(pkt_out.compressed, double_pkt_out.compressed)
        self.assertEqual(pkt_out.signature_length, double_pkt_out.signature_length)
        self.assertEqual(pkt_out.signature, double_pkt_out.signature)
        self.assertEqual(pkt_out.message_payload, double_pkt_out.message_payload)
        self.assertEqual(pkt_out.packet_payload, double_pkt_out.packet_payload)
        self.assertEqual(pkt_out.from_call, double_pkt_out.from_call)
        self.assertEqual(pkt_out.auth_type, double_pkt_out.auth_type)

    def test_double_roundtrip_signed(self):
        """Double round trip with signing"""
        pkt_out = pauth.to_ax25_payload(
            from_call=self.from_call,
            message_payload=self.message_payload,
            sign=True,
        )
        #pkt_out.public_key = self.public_key


        # Parse back
        raw_bytes = pkt_out.packet_payload
        self.assertEqual(True,pkt_out.signed)
        self.assertEqual(self.from_call, pkt_out.from_call)
        self.assertEqual(self.message_payload, pkt_out.message_payload)
        self.assertEqual(self.private_key.sign(self.message_payload), pkt_out.signature)
        #print("part one bytes")
        #bprint(raw_bytes)

        double_pkt_out = pauth.from_ax25_payload(
            from_call=pkt_out.from_call,
            packet_payload=pkt_out.packet_payload
        )
        self.assertEqual(pkt_out.version, double_pkt_out.version)
        self.assertEqual(pkt_out.signed, double_pkt_out.signed)
        self.assertEqual(pkt_out.compressed, double_pkt_out.compressed)
        self.assertEqual(pkt_out.signature_length, double_pkt_out.signature_length)
        self.assertEqual(pkt_out.signature, double_pkt_out.signature)
        self.assertEqual(pkt_out.message_payload, double_pkt_out.message_payload)
        self.assertEqual(pkt_out.packet_payload, double_pkt_out.packet_payload)
        self.assertEqual(pkt_out.from_call, double_pkt_out.from_call)
        self.assertEqual(pkt_out.auth_type, double_pkt_out.auth_type)

if __name__ == "__main__":
    unittest.main()

