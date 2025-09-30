import socket
import urllib.parse
import re
try:
    from distutils.util import strtobool
except ImportError:
    # distutils is deprecated in Python 3.12+
    def strtobool(val):
        """Convert a string representation of truth to true (1) or false (0)."""
        val = val.lower()
        if val in ('y', 'yes', 't', 'true', 'on', '1'):
            return 1
        elif val in ('n', 'no', 'f', 'false', 'off', '0'):
            return 0
        else:
            raise ValueError(f"invalid truth value {val!r}")

from .exceptions import OptionValidationError


def url(address):
    """Sanitize url.

    Converts address to valid HTTP url.
    """
    if address.startswith("http://") or address.startswith("https://"):
        return address
    else:
        return "http://{}".format(address)


def address(addr):
    addr = urllib.parse.urlsplit(addr)
    return addr.netloc or addr.path


def choice(valid_values):
    valid_values = [] if not valid_values else valid_values

    def _enum(value):
        if value not in valid_values:
            raise OptionValidationError("Selected '{}' value isn't correct. Possible values are: {}".format(value, valid_values))

        return value

    return _enum


def ipv4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            raise OptionValidationError("Option have to be valid IP address.")

        if address.count('.') == 3:
            return address
        else:
            raise OptionValidationError("Option have to be valid IP address.")
    except socket.error:
        raise OptionValidationError("Option have to be valid IP address.")

    return address


def mac(address):
    if re.match("[0-9a-f]{2}([:-])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", address.lower()):
        return address.replace('-', ':')
    else:
        raise OptionValidationError("Option have to be valid Mac address.")


def boolify(value):
    """ Function that will translate common strings into bool values

    True -> "True", "t", "yes", "y", "on", "1"
    False -> any other string

    Objects other than string will be transformed using built-in bool() function.
    """
    if isinstance(value, str):
        try:
            return bool(strtobool(value))
        except ValueError:
            return False
    else:
        return bool(value)


def integer(number):
    """ Cast Option value to the integer using int() """
    try:
        return int(number)
    except ValueError:
        raise OptionValidationError("Invalid option. can't cast '{}' to integer.".format(number))


# Alias for boolify to maintain compatibility with existing code
bool = boolify
