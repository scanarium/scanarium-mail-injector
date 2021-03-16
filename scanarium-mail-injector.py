#!/usr/bin/env python3

import configparser
import email
import email.policy
import json
import os
import requests
import sys


class InjectorException(RuntimeError):
    pass


def load_config():
    config = configparser.ConfigParser()
    config_file_abs = os.path.join('/', 'etc', 'scanarium-mail-injector',
                                   'scanarium-mail-injector.conf')
    if os.path.isfile(config_file_abs):
        config.read(config_file_abs)
    return config


CONFIG = load_config()


def get_header_non_empty(mail, name):
    header = mail.get(name)
    if (header is None):
        raise InjectorException(f'Failed to find "{name}" header in email')
    header = header.strip()
    if (len(header)) == 0:
        raise InjectorException(
            f'Failed to non-empty "{name}" header in email')
    return header


def get_from_address(mail):
    header = get_header_non_empty(mail, 'From')
    address = header.rsplit(' ')[-1].strip('<>')
    return address


def assert_valid_message(mail, from_address):
    header = get_header_non_empty(mail, 'Authentication-Results')
    header_parts = header.split(';')
    if len(header_parts) == 0:
        raise InjectorException('No items in authentication results')

    missing_spf = True
    missing_dkim = True
    for raw_header_part in header_parts[1:]:  # The first result is the plain
        # hostname, which is not useful, so we skip over it.
        items = raw_header_part.strip().split(' ')
        if len(items) < 2:
            raise InjectorException(
                'Too few items in authentication results part')
        name_parts = items[0].split('=', 1)
        if len(name_parts) != 2:
            raise InjectorException('Check name parts does not have 2 items')
        name = name_parts[0]
        result = name_parts[1]
        if result != 'pass':
            raise InjectorException(f'Check {name} failed')

        environment = {}
        for item in items[1:]:
            name_parts = item.split('=', 1)
            if len(name_parts) != 2:
                name_parts = ['anon', name_parts[0]]
            environment[name_parts[0]] = name_parts[1]

        if name == 'spf':
            missing_spf = False
            if environment.get('envelope-from', 'none') != from_address:
                raise InjectorException(
                    'SPF marked as passed, although "envelope-from" does not '
                    'match "From"')
        if name == 'dkim':
            missing_spf = False

    if missing_spf and missing_dkim:
        raise InjectorException('Neither SPF nor DKIM is in place')


def get_target_pod(address):
    mapping_path = CONFIG.get('pod', 'mapping')
    with open(mapping_path, 'r') as file:
        mapping = json.load(file)
    pod = mapping[address]
    return pod


def post_part(part, pod):
    pod_domain = CONFIG.get('pod', 'domain')
    pod_path = CONFIG.get('pod', 'path')
    url = f'https://{pod}.{pod_domain}{pod_path}'

    package_name = CONFIG.get('package', 'name')
    package_version = CONFIG.get('package', 'version')
    package_url = CONFIG.get('package', 'url')
    package_email = CONFIG.get('package', 'email')
    headers = {
        'user-agent': f'{package_name}/{package_version} '
        f'({package_url}; {package_email})'
    }
    auth = (
        CONFIG.get('auth', 'username'),
        CONFIG.get('auth', 'password'),
    )
    files = {'data': part.get_content()}
    response = requests.post(url, files=files, auth=auth, headers=headers)
    if response.status_code != requests.codes.ok:
        raise InjectorException('Injection gave status {response.status_code}')


def post_images(mail, pod):
    for part in mail.walk():
        post = part.get_content_type() in ['image/jpeg']

        if not post:
            filename = part.get_filename()
            if filename is not None:
                suffix = filename.split('.', 1)[-1]
                post = suffix in ['jpg']

        if post:
            post_part(part, pod)


def parse():
    mail = email.message_from_bytes(
        sys.stdin.buffer.read(),
        policy=email.policy.default)

    from_address = get_from_address(mail)
    assert_valid_message(mail, from_address)
    post_images(mail, get_target_pod(from_address))


if __name__ == "__main__":
    parse()
