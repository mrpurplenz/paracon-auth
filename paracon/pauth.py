# =============================================================================
# Copyright (c) 2025-2030 Richard Edmonds
#
# Author: Richard L Edmonds
# License: MIT License
# =============================================================================

"""
Paracon Auth module

This provides an authentication module for the Paracon application. This
implementation is based on the chattervox protocol v1 from Brannon Dorsey 
described at
https://github.com/brannondorsey/chattervox?tab=readme-ov-file#chattervox-protocol-v1-packet
The intention is to provide a wrapper around the packet byte data
read from and to the AGWPE server from the pserver.py module
conduct signing and verification of those packets and pass the appropriate
authentication status by Enum back through the pserver to the tui for
a differentiated display by way of text colour in the terminal

"""

from enum import Enum


class AuthType(Enum):
    """
    Type used to identify the authentication status for display in 
    Paracon.
    """
    UNKNOWN           = "UN"  # Unknown or not yet determined
    UNSIGNED          = "NS"  # No signature present
    SIGNED_VERIFIED   = "SV"  # Signature present and verified
    SIGNED_NO_PUB     = "SN"  # Signature present but no public key available
    SIGNED_MISMATCH   = "SM"  # Sender call, sig call missmatch
    INVALID           = "IV"  # Signature invalid (forged/tampered)
