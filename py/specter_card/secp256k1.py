"""
Thin ctypes wrapper around libsecp256k1.
Falls back to prebuilt binaries shipped in tests/tests/util/prebuilt/ when the
system library is not found.
"""
import ctypes, os, sys, ctypes.util
from ctypes import (
    byref, c_int, c_uint, c_char_p, c_size_t, c_void_p, POINTER
)

# Flags to pass to context_create.
CONTEXT_VERIFY = 0b0100000001
CONTEXT_SIGN   = 0b1000000001

# Flags to pass to ec_pubkey_serialize.
EC_COMPRESSED   = 0b0100000010
EC_UNCOMPRESSED = 0b0000000010

_PREBUILT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__),
                 "../../tests/tests/util/prebuilt")
)


def _init(flags=CONTEXT_SIGN | CONTEXT_VERIFY):
    library_path = ctypes.util.find_library("secp256k1")
    if library_path is None:
        if sys.platform == "darwin":
            library_path = os.path.join(_PREBUILT_DIR, "libsecp256k1.dylib")
        else:
            library_path = os.path.join(_PREBUILT_DIR, "libsecp256k1.so")

    lib = ctypes.cdll.LoadLibrary(library_path)

    lib.secp256k1_context_create.argtypes = [c_uint]
    lib.secp256k1_context_create.restype = c_void_p

    lib.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
    lib.secp256k1_context_randomize.restype = c_int

    lib.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
    lib.secp256k1_ec_pubkey_create.restype = c_int

    lib.secp256k1_ec_pubkey_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_int]
    lib.secp256k1_ec_pubkey_parse.restype = c_int

    lib.secp256k1_ec_pubkey_serialize.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p, c_uint]
    lib.secp256k1_ec_pubkey_serialize.restype = c_int

    lib.secp256k1_ec_pubkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
    lib.secp256k1_ec_pubkey_tweak_mul.restype = c_int

    lib.secp256k1_ecdsa_signature_parse_der.argtypes = [c_void_p, c_char_p, c_char_p, c_uint]
    lib.secp256k1_ecdsa_signature_parse_der.restype = c_int

    lib.secp256k1_ecdsa_signature_serialize_der.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p]
    lib.secp256k1_ecdsa_signature_serialize_der.restype = c_int

    lib.secp256k1_ecdsa_signature_normalize.argtypes = [c_void_p, c_char_p, c_char_p]
    lib.secp256k1_ecdsa_signature_normalize.restype = c_int

    lib.secp256k1_ecdsa_verify.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
    lib.secp256k1_ecdsa_verify.restype = c_int

    lib.ctx = lib.secp256k1_context_create(flags)
    lib.secp256k1_context_randomize(lib.ctx, os.urandom(32))
    return lib


_secp = _init()


def ec_pubkey_create(secret):
    if len(secret) != 32:
        raise ValueError("Private key must be 32 bytes")
    pub = bytes(64)
    if _secp.secp256k1_ec_pubkey_create(_secp.ctx, pub, secret) == 0:
        raise ValueError("Invalid private key")
    return pub


def ec_pubkey_parse(sec):
    if len(sec) not in (33, 65):
        raise ValueError("Serialized pubkey must be 33 or 65 bytes")
    pub = bytes(64)
    if _secp.secp256k1_ec_pubkey_parse(_secp.ctx, pub, sec, len(sec)) == 0:
        raise ValueError("Failed to parse public key")
    return pub


def ec_pubkey_serialize(pubkey, flag=EC_COMPRESSED):
    if len(pubkey) != 64:
        raise ValueError("Internal pubkey must be 64 bytes")
    sec = bytes(33) if flag == EC_COMPRESSED else bytes(65)
    sz = c_size_t(len(sec))
    if _secp.secp256k1_ec_pubkey_serialize(_secp.ctx, sec, byref(sz), pubkey, flag) == 0:
        raise ValueError("Failed to serialize pubkey")
    return sec


def ec_pubkey_tweak_mul(pub, tweak):
    if len(pub) != 64:
        raise ValueError("Public key must be 64 bytes")
    if len(tweak) != 32:
        raise ValueError("Tweak must be 32 bytes")
    if _secp.secp256k1_ec_pubkey_tweak_mul(_secp.ctx, pub, tweak) == 0:
        raise ValueError("Failed to tweak public key")


def ecdsa_signature_parse_der(der):
    sig = bytes(64)
    if _secp.secp256k1_ecdsa_signature_parse_der(_secp.ctx, sig, der, len(der)) == 0:
        raise ValueError("Failed to parse DER signature")
    return sig


def ecdsa_signature_normalize(sig):
    if len(sig) != 64:
        raise ValueError("Signature must be 64 bytes")
    sig2 = bytes(64)
    _secp.secp256k1_ecdsa_signature_normalize(_secp.ctx, sig2, sig)
    return sig2


def ecdsa_verify(sig, msg, pub):
    if len(sig) != 64 or len(msg) != 32 or len(pub) != 64:
        raise ValueError("sig=64 bytes, msg=32 bytes, pub=64 bytes required")
    return bool(_secp.secp256k1_ecdsa_verify(_secp.ctx, sig, msg, pub))
