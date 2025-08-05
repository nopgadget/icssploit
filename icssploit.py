#!/usr/bin/env python3

import argparse
import logging.handlers
import os
import configparser
from icssploit.interpreter import IcssploitInterpreter

# Define conf
icssploit_conf_file = "icssploit.ini"
icssploit_conf = configparser.ConfigParser(allow_no_value=True)
icssploit_conf.read(icssploit_conf_file)

# Get parameter from conf
log_file_name = icssploit_conf.get("LOG", "log_file_name")
log_max_bytes = icssploit_conf.getint("LOG", "log_max_bytes")
log_level = icssploit_conf.getint("LOG", "log_level")
package_path = icssploit_conf.get("EXTRA_PACKEAGE", "package_path")


# Define logger
log_handler = logging.handlers.RotatingFileHandler(filename=log_file_name, maxBytes=log_max_bytes)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(log_level)
LOGGER.addHandler(log_handler)

parser = argparse.ArgumentParser(description='ICSSploit - ICS Exploitation Framework')
parser.add_argument('-e',
                    '--extra-package-path',
                    metavar='extra_package_path',
                    help='Add extra packet(clients, modules, protocols) to icssploit.')


def icssploit(extra_package_path=package_path):
    if not os.path.isdir(extra_package_path):
        extra_package_path = None
    icssploit_interpreter = IcssploitInterpreter(extra_package_path)
    icssploit_interpreter.start()


if __name__ == "__main__":
    args = parser.parse_args()
    if args.extra_package_path:
            icssploit(extra_package_path=args.extra_package_path)
    else:
        icssploit() 