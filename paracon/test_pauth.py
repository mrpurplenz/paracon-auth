import unittest
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

import pauth


class TestPauthPacket(unittest.TestCase):

    def setUp(self):
        # Generate a temporary key pair for each test
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # Encode keys to PEM (optional, for debug/info)
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        self.message = b"Hello Chattervox!"

    def sign_message(self, msg: bytes) -> bytes:
        """Helper: sign message bytes with the test private key."""
        signature = self.private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        return signature

    def test_unsigned_round_trip(self):
        """Unsigned packets should survive assemble→disassemble unchanged and be UNSIGNED."""
        pkt = pauth.Packet()
        pkt.version = 1
        pkt.byte_message = self.message
        pkt.signature = None

        assembled = pkt.assemble(sign=False)

        new_pkt = pauth.Packet()
        msg_out, auth_type = new_pkt.disassemble(assembled, sender_call="ZL2DRS-4")

        self.assertEqual(msg_out, self.message)
        self.assertEqual(auth_type, pauth.AuthType.UNSIGNED)

    def test_signed_round_trip(self):
        """Signed packets should be parsed and marked SIGNED_VERIFIED in placeholder logic."""
        signature = self.sign_message(self.message)

        pkt = pauth.Packet()
        pkt.version = 1
        pkt.byte_message = self.message
        pkt.signature = signature

        assembled = pkt.assemble(sign=True)

        new_pkt = pauth.Packet()
        msg_out, auth_type = new_pkt.disassemble(assembled, sender_call="ZL2DRS-4")

        self.assertEqual(msg_out, self.message)
        self.assertIn(auth_type, [pauth.AuthType.SIGNED_VERIFIED, pauth.AuthType.UNTRUSTED])

    def test_bad_packet(self):
        """Garbage bytes should be marked UNKNOWN."""
        garbage = b"\x00\x01\x02\x03garbage!"
        new_pkt = pauth.Packet()
        msg_out, auth_type = new_pkt.disassemble(garbage, sender_call="ZL2DRS-4")

        self.assertEqual(msg_out, garbage)
        self.assertEqual(auth_type, pauth.AuthType.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
