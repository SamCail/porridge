import contextlib
import os
import re
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    cast,
    c_char_p,
    c_size_t,
    c_int,
    c_uint8,
    c_uint32,
    c_void_p,
    string_at,
)

from .utils import (
    b64_decode_raw,
    b64_encode_raw,
    check_types,
    ensure_bytes,
    string_types,
)
from .exceptions import (
    EncodedPasswordError,
    MissingKeyError,
    ParameterError,
    PorridgeError,
)

__all__ = ("Porridge",)

ARGON2_LIB = CDLL(os.path.join(os.path.dirname(__file__), "libargon2.so.0"))


class Argon2Type(c_int):
    Argon2_d = 0
    Argon2_i = 1
    Argon2_id = 2


class Argon2Version(c_int):
    ARGON2_VERSION_10 = 0x10
    ARGON2_VERSION_13 = 0x13
    ARGON2_VERSION_NUMBER = 0x13


class Argon2ErrorCodes(c_int):
    ARGON2_OK = 0

    ARGON2_OUTPUT_PTR_NULL = -1

    ARGON2_OUTPUT_TOO_SHORT = -2
    ARGON2_OUTPUT_TOO_LONG = -3

    ARGON2_PWD_TOO_SHORT = -4
    ARGON2_PWD_TOO_LONG = -5

    ARGON2_SALT_TOO_SHORT = -6
    ARGON2_SALT_TOO_LONG = -7

    ARGON2_AD_TOO_SHORT = -8
    ARGON2_AD_TOO_LONG = -9

    ARGON2_SECRET_TOO_SHORT = -10
    ARGON2_SECRET_TOO_LONG = -11

    ARGON2_TIME_TOO_SMALL = -12
    ARGON2_TIME_TOO_LARGE = -13

    ARGON2_MEMORY_TOO_LITTLE = -14
    ARGON2_MEMORY_TOO_MUCH = -15

    ARGON2_LANES_TOO_FEW = -16
    ARGON2_LANES_TOO_MANY = -17

    ARGON2_PWD_PTR_MISMATCH = -18  # /* NULL ptr with non-zero length */
    ARGON2_SALT_PTR_MISMATCH = -19  # /* NULL ptr with non-zero length */
    ARGON2_SECRET_PTR_MISMATCH = -20  # /* NULL ptr with non-zero length */
    ARGON2_AD_PTR_MISMATCH = -21  # /* NULL ptr with non-zero length */

    ARGON2_MEMORY_ALLOCATION_ERROR = -22

    ARGON2_FREE_MEMORY_CBK_NULL = -23
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24

    ARGON2_INCORRECT_PARAMETER = -25
    ARGON2_INCORRECT_TYPE = -26

    ARGON2_OUT_PTR_MISMATCH = -27

    ARGON2_THREADS_TOO_FEW = -28
    ARGON2_THREADS_TOO_MANY = -29

    ARGON2_MISSING_ARGS = -30

    ARGON2_ENCODING_FAIL = -31

    ARGON2_DECODING_FAIL = -32

    ARGON2_THREAD_FAIL = -33

    ARGON2_DECODING_LENGTH_FAIL = -34

    ARGON2_VERIFY_MISMATCH = -35


# These parameters should be increased regularly to keep boiling slow
# on new hardware
DEFAULT_RANDOM_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 512
DEFAULT_PARALLELISM = 4
DEFAULT_PARAMETER_THRESHOLD = 4

ARGON2_FLAG_CLEAR_PASSWORD = c_uint32(1 << 0)
ARGON2_FLAG_CLEAR_SECRET = c_uint32(1 << 1)
ARGON2_DEFAULT_FLAGS = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET

ALLOCATE_FPTR = CFUNCTYPE(c_int, POINTER(c_uint8), c_size_t)
DEALLOCATE_FPTR = CFUNCTYPE(None, POINTER(c_uint8), c_size_t)


class Argon2Context(Structure):
    _fields_ = [
        ("out", POINTER(c_uint8)),  # Pointer to output array
        ("outlen", c_uint32),  # Length of output
        ("pwd", POINTER(c_uint8)),  # Pointer to password array
        ("pwdlen", c_uint32),  # Length of password
        ("salt", POINTER(c_uint8)),  # Pointer to salt array
        ("saltlen", c_uint32),  # Length of salt
        ("secret", POINTER(c_uint8)),  # Pointer to secret (key) array
        ("secretlen", c_uint32),  # Length of secret
        ("ad", POINTER(c_uint8)),  # Pointer to associated data array
        ("adlen", c_uint32),  # Length of associated data
        ("t_cost", c_uint32),  # Time cost (number of passes)
        ("m_cost", c_uint32),  # Memory cost (KB)
        ("lanes", c_uint32),  # Number of lanes (degree of parallelism)
        ("threads", c_uint32),  # Maximum number of threads
        ("version", c_uint32),  # Version number
        (
            "allocate_cbk",
            POINTER(c_void_p),
        ),  # Memory allocator callback function pointer
        ("free_cbk", POINTER(c_void_p)),  # Memory deallocator callback function pointer
        ("flags", c_uint32),  # Flags (options for clearing memory)
    ]


# This regex validates the spec from
# https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
ENCODED_HASH_RE = re.compile(
    r"".join(
        [
            r"^\$argon2i\$",
            r"(?:v=(?P<version>[0-9]{1,3})\$)?",
            r"".join(
                [
                    r"m=(?P<memory_cost>[0-9]{1,10})",
                    r",t=(?P<time_cost>[0-9]{1,10})",
                    r",p=(?P<parallelism>[0-9]{1,3})",
                    r"(?:,keyid=(?P<keyid>[a-zA-Z0-9+/]{0,11}))?",  # optional
                    r"(?:,data=(?P<data>[a-zA-Z0-9+/]{0,43}))?",  # optional, unused
                ]
            ),
            r"\$(?P<salt>[a-zA-Z0-9+/]{11,64})\$",
            r"(?P<hash>[a-zA-Z0-9+/]{16,86})",
        ]
    )
    + r"$"
)


class Porridge(object):
    r"""
    Helper class to boil passwords with sensible defaults and server-side
    secrets.

    :param str secrets: A comma-separated string of *keyid:key* pairs that will
        be used as server-side secrets. The first element in the list will be
        used to boil new passwords, the others to verify old ones.
    :param int time_cost: Defines the amount of computation realized and
        therefore the execution time, given in number of iterations.
    :param int memory_cost: Defines the memory usage, given in kibibytes_.
    :param int parallelism: Defines the number of threads used
    :param int hash_len: Length of the raw hash in bytes.
    :param int salt_len: Length of random salt to be generated for each
        password.
    :param int parameter_threshold: A multiplier that sets the threshold for
        how much higher parameters in boiled passwords can be above our own
        parameters before we refuse the process them.
    :param str encoding: Boiling is always performed on bytes, thus if unicode
        strings are given to either :meth:`boil` of :meth:`verify` this encoding
        will be used to encode the password to bytes.

    .. _salt: https://en.wikipedia.org/wiki/Salt_(cryptography)
    .. _kibibytes: https://en.wikipedia.org/wiki/Binary_prefix#kibi
    """

    def __init__(
        self,
        secrets,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        hash_len=DEFAULT_HASH_LENGTH,
        salt_len=DEFAULT_RANDOM_SALT_LENGTH,
        parameter_threshold=DEFAULT_PARAMETER_THRESHOLD,
        encoding="utf-8",
    ):
        e = check_types(
            secrets=(secrets, string_types),
            time_cost=(time_cost, int),
            memory_cost=(memory_cost, int),
            parallelism=(parallelism, int),
            hash_len=(hash_len, int),
            salt_len=(salt_len, int),
            parameter_threshold=(parameter_threshold, int),
            encoding=(encoding, string_types),
        )
        if e:
            raise TypeError(e)

        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        self.encoding = encoding
        if parameter_threshold < 1:
            raise ValueError("parameter_threshold must be at least 1")
        self.parameter_threshold = parameter_threshold

        self.secret_map = {}
        self.secret = None
        self.keyid = None
        for secret_pair in secrets.split(","):
            keyid, secret = secret_pair.split(":", 1)
            keyid = keyid.encode("utf-8")
            secret = secret.encode("utf-8")
            if self.secret is None:
                self.secret = secret
                self.keyid = keyid
            self.secret_map[keyid] = secret

        self._self_check()

    def _self_check(self):
        """
        Perform a single run of boiling to ensure we have a valid
        combination of parameters.
        """
        self.boil("dummy")

    def boil(self, password):
        """
        Boil *password* and return and boiled password that can be stored in a
        database.

        :param password: Password to boil.
        :type password: ``bytes`` or ``unicode``

        :raises porridge.PorridgeError: If verification fails to complete due
            to not being able to spawn enough threads or allocate enough memory.

        :rtype: unicode
        """
        e = check_types(password=(password, string_types + (bytes,)))
        if e:
            raise TypeError(e)

        salt = os.urandom(self.salt_len)
        context_params = dict(
            salt=salt,
            password=ensure_bytes(password, self.encoding),
            secret=self.secret,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
        )
        with argon2_context(**context_params) as ctx:
            result = compute_hash(ctx)

            if result != Argon2ErrorCodes.ARGON2_OK:
                error_message = argon2_error_message(result)
                if is_operational_error(result):
                    raise PorridgeError(error_message)
                else:
                    raise ParameterError(error_message)

            raw_hash = bytes(string_at(ctx.out, ctx.outlen))
        return self._encode(raw_hash, salt)

    def verify(self, password, boiled):
        """
        Verify that *password* matches *boiled*.

        :param password: The password to verify.
        :type password: ``bytes`` or ``unicode``
        :param unicode boiled: An boiled password as returned from
            :meth:`Porridge.boil`.

        :raises porridge.PorridgeError: If verification fails to complete due
            to not being able to spawn enough threads or allocate enough memory.

        :return: ``True`` if *password* is valid, otherwise ``False``.
        :rtype: bool
        """
        e = check_types(
            password=(password, string_types + (bytes,)),
            boiled=(boiled, string_types),
        )
        if e:
            raise TypeError(e)

        if len(boiled) > 265:
            # Ensure we don't DDoS ourselves if the database holds corrupt values
            raise EncodedPasswordError(
                "Encoded password exceeds maximum length of 265, was {length}".format(
                    length=len(boiled)
                )
            )

        context_params = parse_boiled(boiled)
        self._verify_parameters_within_threshold(context_params)
        raw_hash = context_params.pop("raw_hash")

        context_params.update(
            dict(
                hash_len=len(raw_hash),
                password=self._ensure_bytes(password),
            )
        )

        keyid = context_params.get("keyid")
        if keyid:
            del context_params["keyid"]
            secret = self.secret_map.get(keyid)
            if not secret:
                raise MissingKeyError(keyid.decode("utf-8"))
            context_params["secret"] = secret

        with argon2_context(**context_params) as ctx:
            result = verify_hash(ctx, raw_hash)

        if result == Argon2ErrorCodes.ARGON2_OK:
            return True
        elif result == Argon2ErrorCodes.ARGON2_VERIFY_MISMATCH:
            return False
        else:
            error_message = argon2_error_message(result)
            raise PorridgeError(error_message)

    def needs_update(self, boiled):
        """
        Check if the parameters in *boiled* are old and the password should be
        re-boiled.

        :param unicode boiled: An boiled password as returned from
            :meth:`Porridge.boil`.

        :rtype: bool
        """
        parsed = parse_boiled(boiled)
        if parsed["version"] < Argon2Version.ARGON2_VERSION_NUMBER:
            return True

        if parsed["parallelism"] < self.parallelism:
            return True

        if parsed["memory_cost"] < self.memory_cost:
            return True

        if parsed["time_cost"] < self.time_cost:
            return True

        if len(parsed["salt"]) < self.salt_len:
            return True

        if len(parsed["raw_hash"]) < self.hash_len:
            return True

        if parsed.get("keyid") != self.keyid:
            return True

        return False

    def _ensure_bytes(self, s):
        return ensure_bytes(s, self.encoding)

    def _verify_parameters_within_threshold(self, parameters):
        for parameter in ("time_cost", "memory_cost", "parallelism"):
            given_parameter = parameters[parameter]
            our_parameter = getattr(self, parameter)
            if given_parameter > our_parameter * self.parameter_threshold:
                raise EncodedPasswordError(
                    "%s exceeds threshold of what we will process" % parameter
                )

    def _encode(self, raw_hash, salt):
        template = (
            "${algo}$v={version}$m={m_cost},t={t_cost},p={parallelism}"
            ",keyid={keyid}${salt}${hash}"
        )
        return template.format(
            algo="argon2i",
            t_cost=self.time_cost,
            m_cost=self.memory_cost,
            parallelism=self.parallelism,
            salt=b64_encode_raw(salt),
            hash=b64_encode_raw(raw_hash),
            version=Argon2Version.ARGON2_VERSION_NUMBER,
            keyid=self.keyid.decode("utf-8"),
        )

    def __str__(self):
        return (
            "Porridge(key='{key}', memory_cost={memory_cost}, "
            "time_cost={time_cost}, parallelism={parallelism})"
        ).format(
            key=self.keyid.decode("utf-8"),
            memory_cost=self.memory_cost,
            time_cost=self.time_cost,
            parallelism=self.parallelism,
        )

    def __repr__(self):
        return (
            "Porridge(key='{key}', memory_cost={memory_cost}, time_cost={time_cost}, "
            "parallelism={parallelism}, hash_len={hash_len}, salt_len={salt_len}, "
            "parameter_threshold={parameter_threshold}, encoding='{encoding}')"
        ).format(
            key=self.keyid.decode("utf-8"),
            memory_cost=self.memory_cost,
            time_cost=self.time_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            salt_len=self.salt_len,
            parameter_threshold=self.parameter_threshold,
            encoding=self.encoding,
        )


def parse_boiled(boiled):
    match = ENCODED_HASH_RE.match(boiled)
    if not match:
        raise EncodedPasswordError("Encoded password is on unknown format", boiled)
    version = match.group("version")
    if version:
        version = int(version)
    else:
        # Default to the old version as only ARGON2_VERSION_13 includes it in the boiled string
        version = Argon2Version.ARGON2_VERSION_10

    salt = b64_decode_raw(match.group("salt"))
    raw_hash = b64_decode_raw(match.group("hash"))
    time_cost = int(match.group("time_cost"))
    memory_cost = int(match.group("memory_cost"))
    parallelism = int(match.group("parallelism"))

    parsed = dict(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        raw_hash=raw_hash,
        salt=salt,
        version=version,
    )

    keyid = match.group("keyid")
    if keyid:
        parsed["keyid"] = keyid.encode("utf-8")

    return parsed


def argon2_error_message(error_code):
    ARGON2_LIB.argon2_error_message.argtype = [c_int]
    ARGON2_LIB.argon2_error_message.restype = c_char_p

    return ARGON2_LIB.argon2_error_message(error_code).decode("utf-8")


def is_operational_error(error_code):
    return error_code in {
        Argon2ErrorCodes.ARGON2_THREAD_FAIL,
        Argon2ErrorCodes.ARGON2_MEMORY_ALLOCATION_ERROR,
    }


def compute_hash(context):
    """Minimal wrapper around argon2_ctx to enable mocking"""

    ARGON2_LIB.argon2_ctx.argtypes = [POINTER(Argon2Context), Argon2Type]
    ARGON2_LIB.argon2_ctx.restype = c_int
    return ARGON2_LIB.argon2_ctx(context, Argon2Type.Argon2_i)


def verify_hash(context, raw_hash):
    """Minimal wrapper around argon2i_verify_ctx to enable mocking"""

    ARGON2_LIB.argon2i_verify_ctx.argtypes = [POINTER(Argon2Context), c_char_p]
    ARGON2_LIB.argon2i_verify_ctx.restype = c_int
    return ARGON2_LIB.argon2i_verify_ctx(context, raw_hash)


@contextlib.contextmanager
def argon2_context(
    password=None,  # bytes
    salt=None,
    secret=None,
    hash_len=DEFAULT_HASH_LENGTH,
    time_cost=DEFAULT_TIME_COST,
    memory_cost=DEFAULT_MEMORY_COST,
    parallelism=DEFAULT_PARALLELISM,
    flags=ARGON2_DEFAULT_FLAGS,
    version=Argon2Version.ARGON2_VERSION_NUMBER,
):
    csalt = (c_uint8 * len(salt))(*salt)
    cout = (c_uint8 * hash_len)()
    cpwd = (c_uint8 * len(password))(*password)

    if secret:
        csecret = (c_uint8 * len(secret))(*secret)
        secret_len = len(secret)
    else:
        csecret = None
        secret_len = 0

    context = Argon2Context()
    context.out = cout
    context.outlen = hash_len
    context.pwd = cpwd
    context.pwdlen = len(password)
    context.salt = csalt
    context.saltlen = len(salt)
    context.secret = csecret
    context.secretlen = secret_len
    context.ad = POINTER(c_uint8)(cast(c_void_p(0), POINTER(c_uint8)))
    context.adlen = 0
    context.t_cost = time_cost
    context.m_cost = memory_cost
    context.lanes = parallelism
    context.threads = parallelism
    context.version = version
    context.allocate_cbk = None
    context.free_cbk = None
    context.flags = flags

    yield context
