"""
SecureApplet – base class for all PIN-protected applets.

Provides:
  - Plaintext get_random / get_pubkey APDUs
  - Secure-channel helpers (open_secure_channel, echo, secure_random)
  - PIN management (status, set, unset, unlock, lock, change)
"""
from ..connection import ISOException
from ..securechannel import SecureChannel, SecureError

_CLA           = 0xB0
_INS_RANDOM    = 0xB1
_INS_PUBKEY    = 0xB2

# Secure-channel sub-commands
_CMD_ECHO        = 0x00
_CMD_RANDOM      = 0x01
_CMD_PIN         = 0x03

_SUBCMD_PIN_STATUS  = 0x00
_SUBCMD_PIN_UNLOCK  = 0x01
_SUBCMD_PIN_LOCK    = 0x02
_SUBCMD_PIN_CHANGE  = 0x03
_SUBCMD_PIN_SET     = 0x04
_SUBCMD_PIN_UNSET   = 0x05

_encode = lambda d: bytes([len(d)]) + d

AID      = "B00B5111FF01"
APPLET   = "toys.SecureApplet"
CLASSDIR = "Secure"

# PIN status third-byte values
PIN_DISABLED  = 0x00
PIN_LOCKED    = 0x01
PIN_UNLOCKED  = 0x02
PIN_BRICKED   = 0x03


class SecureApplet:
    """
    High-level interface to the SecureApplet (and subclasses).

    Parameters
    ----------
    connection :
        A connected :class:`~specter_card.connection.Card` or
        :class:`~specter_card.connection.Simulator` instance.
    """

    AID      = AID
    APPLET   = APPLET
    CLASSDIR = CLASSDIR

    def __init__(self, connection):
        self.conn = connection

    # ------------------------------------------------------------------
    # Plaintext APDUs
    # ------------------------------------------------------------------
    def get_random(self) -> bytes:
        """Return 32 random bytes from the card (unauthenticated)."""
        return self.conn.request(bytes([_CLA, _INS_RANDOM, 0x00, 0x00]))

    def get_pubkey(self) -> bytes:
        """
        Return the card's static 65-byte uncompressed public key.

        This key identifies the card and is used to open a secure channel.
        """
        return self.conn.request(bytes([_CLA, _INS_PUBKEY, 0x00, 0x00]))

    # ------------------------------------------------------------------
    # Secure channel helpers
    # ------------------------------------------------------------------
    def open_secure_channel(self, mode: str = "es") -> SecureChannel:
        """
        Open and return a :class:`~specter_card.securechannel.SecureChannel`.

        Parameters
        ----------
        mode : str
            ``"es"`` (host-ephemeral/card-static, default) or ``"ee"``.
        """
        sc = SecureChannel(self.conn, mode=mode)
        sc.open()
        return sc

    def echo(self, sc: SecureChannel, data: bytes) -> bytes:
        """Echo *data* through the secure channel (useful for testing)."""
        return sc.request(bytes([_CMD_ECHO, 0x00]) + data)

    def secure_random(self, sc: SecureChannel) -> bytes:
        """Return 32 random bytes over the secure channel."""
        return sc.request(bytes([_CMD_RANDOM, 0x00]))

    # ------------------------------------------------------------------
    # PIN management (all over secure channel)
    # ------------------------------------------------------------------
    def pin_status(self, sc: SecureChannel) -> dict:
        """
        Return a dict with PIN status information.

        Keys:
          - ``attempts_left`` – remaining unlock attempts
          - ``max_attempts``  – total allowed attempts (usually 10)
          - ``status``        – ``"disabled"``, ``"locked"``, ``"unlocked"``, or ``"bricked"``
        """
        raw = sc.request(bytes([_CMD_PIN, _SUBCMD_PIN_STATUS]))
        left, total, state = raw[0], raw[1], raw[2]
        state_map = {
            PIN_DISABLED: "disabled",
            PIN_LOCKED:   "locked",
            PIN_UNLOCKED: "unlocked",
            PIN_BRICKED:  "bricked",
        }
        return {
            "attempts_left": left,
            "max_attempts":  total,
            "status":        state_map.get(state, f"unknown(0x{state:02x})"),
        }

    def set_pin(self, sc: SecureChannel, pin: bytes) -> None:
        """
        Enable PIN and set it to *pin* (up to 32 bytes).

        Raises :exc:`~specter_card.securechannel.SecureError` with code ``0506``
        if a PIN is already set.
        """
        sc.request(bytes([_CMD_PIN, _SUBCMD_PIN_SET]) + pin)

    def unset_pin(self, sc: SecureChannel, pin: bytes) -> None:
        """Disable PIN using the current *pin* value."""
        sc.request(bytes([_CMD_PIN, _SUBCMD_PIN_UNSET]) + pin)

    def unlock(self, sc: SecureChannel, pin: bytes) -> None:
        """
        Unlock the card using *pin*.

        Raises :exc:`~specter_card.securechannel.SecureError` with code ``0502``
        on wrong PIN or ``0503`` if no attempts remain.
        """
        sc.request(bytes([_CMD_PIN, _SUBCMD_PIN_UNLOCK]) + pin)

    def lock(self, sc: SecureChannel) -> None:
        """Lock the card."""
        sc.request(bytes([_CMD_PIN, _SUBCMD_PIN_LOCK]))

    def change_pin(self, sc: SecureChannel, old_pin: bytes, new_pin: bytes) -> None:
        """Change PIN from *old_pin* to *new_pin*."""
        sc.request(bytes([_CMD_PIN, _SUBCMD_PIN_CHANGE]) + _encode(old_pin) + _encode(new_pin))
