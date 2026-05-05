"""
Secure channel implementation compatible with the JavaCard SecureApplet.

Supports *es* (host-ephemeral / card-static) and *ee* (both ephemeral) modes.
"""
import hashlib, hmac, os
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from . import secp256k1

_encode = lambda d: bytes([len(d)]) + d

HMAC_LEN = 14

# APDU bytes
_CLA = 0xB0
_INS_GET_PUBKEY      = 0xB2
_INS_OPEN_SE         = 0xB4  # es mode
_INS_OPEN_EE         = 0xB5  # ee mode
_INS_SECURE_MESSAGE  = 0xB6
_INS_CLOSE           = 0xB7


class SecureError(Exception):
    """Raised when the card returns a non-9000 code inside the secure channel."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"Secure channel error: {code}")


class SecureChannel:
    """
    Encrypted and authenticated channel to an applet derived from SecureApplet.

    Parameters
    ----------
    card :
        A :class:`~specter_card.connection.Card` or
        :class:`~specter_card.connection.Simulator` instance.
    mode : str
        ``"es"`` (default) or ``"ee"``.
    """

    def __init__(self, card, mode: str = "es"):
        self.card = card
        self.mode = mode
        self.iv = 0
        self.is_open = False
        self._card_pubkey = None
        self._card_aes_key = None
        self._host_aes_key = None
        self._card_mac_key = None
        self._host_mac_key = None

    # ------------------------------------------------------------------
    # Key-exchange helpers
    # ------------------------------------------------------------------
    def _get_card_pubkey(self):
        sec = self.card.request(bytes([_CLA, _INS_GET_PUBKEY, 0x00, 0x00]))
        self._card_pubkey = secp256k1.ec_pubkey_parse(sec)
        return self._card_pubkey

    def _derive_keys(self, shared_secret: bytes) -> bytes:
        self._host_aes_key = hashlib.sha256(b"host_aes" + shared_secret).digest()
        self._card_aes_key = hashlib.sha256(b"card_aes" + shared_secret).digest()
        self._host_mac_key = hashlib.sha256(b"host_mac" + shared_secret).digest()
        self._card_mac_key = hashlib.sha256(b"card_mac" + shared_secret).digest()

    # ------------------------------------------------------------------
    # Open / close
    # ------------------------------------------------------------------
    def open(self, mode: str = None):
        """Establish the secure channel."""
        if mode is not None:
            self.mode = mode

        if self._card_pubkey is None:
            self._get_card_pubkey()

        secret = os.urandom(32)
        host_prv = secret
        host_pub = secp256k1.ec_pubkey_create(secret)
        host_pub_bytes = secp256k1.ec_pubkey_serialize(host_pub, secp256k1.EC_UNCOMPRESSED)

        if self.mode == "ee":
            res = self.card.request(
                bytes([_CLA, _INS_OPEN_EE, 0x00, 0x00]) + _encode(host_pub_bytes)
            )
            s = BytesIO(res)
            card_pub_bytes = s.read(65)
            card_pub = secp256k1.ec_pubkey_parse(card_pub_bytes)
            secp256k1.ec_pubkey_tweak_mul(card_pub, secret)
            shared_x = secp256k1.ec_pubkey_serialize(card_pub)[1:33]
            shared_secret = hashlib.sha256(shared_x).digest()
            self._derive_keys(shared_secret)
            recv_hmac = s.read(HMAC_LEN)
            h = hmac.new(self._card_mac_key, card_pub_bytes, digestmod="sha256")
            if h.digest()[:HMAC_LEN] != recv_hmac:
                raise RuntimeError("HMAC mismatch during EE channel open")
            # verify card signature
            data_signed = card_pub_bytes + recv_hmac
            raw_sig = s.read()
            sig = secp256k1.ecdsa_signature_parse_der(raw_sig)
            sig = secp256k1.ecdsa_signature_normalize(sig)
            if not secp256k1.ecdsa_verify(sig, hashlib.sha256(data_signed).digest(), self._card_pubkey):
                raise RuntimeError("Invalid card signature during EE channel open")
        else:
            # es mode (default)
            res = self.card.request(
                bytes([_CLA, _INS_OPEN_SE, 0x00, 0x00]) + _encode(host_pub_bytes)
            )
            s = BytesIO(res)
            nonce_card = s.read(32)
            recv_hmac = s.read(HMAC_LEN)
            # derive shared secret using card static pubkey
            pub_copy = secp256k1.ec_pubkey_parse(
                secp256k1.ec_pubkey_serialize(self._card_pubkey, secp256k1.EC_UNCOMPRESSED)
            )
            secp256k1.ec_pubkey_tweak_mul(pub_copy, secret)
            shared_x = secp256k1.ec_pubkey_serialize(pub_copy)[1:33]
            secret_with_nonce = hashlib.sha256(shared_x + nonce_card).digest()
            self._derive_keys(secret_with_nonce)
            h = hmac.new(self._card_mac_key, nonce_card, digestmod="sha256")
            if h.digest()[:HMAC_LEN] != recv_hmac:
                raise RuntimeError("HMAC mismatch during ES channel open")
            data_signed = nonce_card + recv_hmac
            sig = secp256k1.ecdsa_signature_parse_der(s.read())
            sig = secp256k1.ecdsa_signature_normalize(sig)
            if not secp256k1.ecdsa_verify(sig, hashlib.sha256(data_signed).digest(), self._card_pubkey):
                raise RuntimeError("Invalid card signature during ES channel open")

        self.iv = 0
        self.is_open = True

    def close(self):
        """Ask the card to close the channel and mark it as closed locally."""
        self.card.request(bytes([_CLA, _INS_CLOSE, 0x00, 0x00]))
        self.is_open = False

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------
    def _encrypt(self, data: bytes) -> bytes:
        d = data + b"\x80"
        if len(d) % 16:
            d += b"\x00" * (16 - len(d) % 16)
        iv = self.iv.to_bytes(16, "big")
        cipher = Cipher(algorithms.AES(self._host_aes_key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(d) + enc.finalize()
        h = hmac.new(self._host_mac_key, iv + ct, digestmod="sha256")
        return ct + h.digest()[:HMAC_LEN]

    def _decrypt(self, ct: bytes) -> bytes:
        recv_hmac = ct[-HMAC_LEN:]
        ct = ct[:-HMAC_LEN]
        iv = self.iv.to_bytes(16, "big")
        h = hmac.new(self._card_mac_key, iv + ct, digestmod="sha256")
        if h.digest()[:HMAC_LEN] != recv_hmac:
            raise RuntimeError("HMAC mismatch in card response")
        cipher = Cipher(algorithms.AES(self._card_aes_key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        plain = dec.update(ct) + dec.finalize()
        # strip M2 padding
        parts = plain.split(b"\x80")
        if len(parts) == 1 or parts[-1].replace(b"\x00", b""):
            raise RuntimeError("Invalid M2 padding in card response")
        return b"\x80".join(parts[:-1])

    # ------------------------------------------------------------------
    # Send / receive over secure channel
    # ------------------------------------------------------------------
    def request(self, data: bytes) -> bytes:
        """
        Send *data* encrypted over the secure channel.

        Automatically re-opens the channel if iv wraps or the channel is closed.
        Raises :exc:`SecureError` if the card returns a non-9000 status inside
        the encrypted envelope.
        """
        if self.iv >= 2 ** 16 or not self.is_open:
            self.open()
        ct = self._encrypt(data)
        res = self.card.request(
            bytes([_CLA, _INS_SECURE_MESSAGE, 0x00, 0x00]) + _encode(ct)
        )
        plaintext = self._decrypt(res)
        self.iv += 1
        if plaintext[:2] == b"\x90\x00":
            return plaintext[2:]
        raise SecureError(plaintext[:2].hex())
