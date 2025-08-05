#!/usr/bin/env python3

import argparse
import logging.handlers
import os
from src.interpreter import IcssploitInterpreter
from src.config import (
    LOG_FILE_NAME,
    LOG_MAX_BYTES,
    LOG_LEVEL,
    EXTRA_PACKAGE_PATH,
    APP_NAME,
    APP_VERSION,
    GITHUB_URL
)


# Define logger
log_handler = logging.handlers.RotatingFileHandler(filename=LOG_FILE_NAME, maxBytes=LOG_MAX_BYTES)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(LOG_LEVEL)
LOGGER.addHandler(log_handler)

parser = argparse.ArgumentParser(description=f'{APP_NAME} - ICS Exploitation Framework')
parser.add_argument('-e',
                    '--extra-package-path',
                    metavar='extra_package_path',
                    help='Add extra packet(clients, modules, protocols) to icssploit.')
parser.add_argument('--version',
                    action='version',
                    version=f'{APP_NAME} {APP_VERSION}')


def icssploit(extra_package_path=EXTRA_PACKAGE_PATH):
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