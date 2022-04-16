import json

import click
import os
from pathlib import Path
import logging

import keycloak
from keycloak import KeycloakOpenID

from config import settings


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.staging.nglp.org/auth/')
@click.option('--auth_file',
              help='The location in which to store the auth file',
              default=os.path.join(Path.home(), '.phonehomeauth'))
@click.option('--realm_name',
              help='The realm name',
              default="arizona-nglp")
def get_keycloak_token(username, password, server, auth_file, realm_name):
    """
    Get an auth token from a keycloak server
    """
    username = username if username else settings.username
    password = password if password else settings.password

    return _get_keycloak_token(username=username, password=password,
                               server=server, auth_file=auth_file,
                               realm_name=realm_name)


def _get_keycloak_token(username, password, server, auth_file, realm_name):
    log = logging.getLogger("rich")
    tokens = {}

    auth_file = auth_file + realm_name
    # parse the existing keyfile into a dictionary
    my_file = Path(auth_file)

    if my_file.is_file():
        # file exists
        with open(auth_file, 'r') as auth_file_handle:
            try:
                tokens = json.load(auth_file_handle)
            except json.decoder.JSONDecodeError:
                tokens = {}
    else:
        tokens = {}

    try:
        keycloak_openid = KeycloakOpenID(
            server_url=server,
            client_id="WDP-Password",
            realm_name=realm_name,
            client_secret_key=settings.client_secret_key[realm_name])

        # Get WellKnow
        config_well_know = keycloak_openid.well_know()

        # get a token
        if server in tokens:
            token = keycloak_openid.token(username, password,
                                          scope='openid')
            token = keycloak_openid.refresh_token(token['refresh_token'])
        else:
            token = keycloak_openid.token(username, password,
                                          scope='openid')
    except keycloak.exceptions.KeycloakGetError as e:
        log.error(
            '[red]Unable to fetch token from keycloak server: [/]'
            '{}'.format(e), extra={'markup': True})
        return None
    except keycloak.exceptions.KeycloakAuthenticationError:
        log.error(
            '[red]Authentication error: [/]bad credentials'
            , extra={'markup': True})
        return None

    # save the tokens back into the auth file
    tokens[server] = token

    with open(auth_file, 'w') as auth_file_handle:
        json.dump(tokens, auth_file_handle)

    return tokens[server]


def get_token(username, password, server,
              auth_file=os.path.join(Path.home(), '.phonehomeauth'),
              refresh=False,
              realm_name=None):
    log = logging.getLogger("rich")
    tokens = {}

    auth_file = auth_file + realm_name

    # parse the existing keyfile into a dictionary
    my_file = Path(auth_file)

    if my_file.is_file():
        # file exists
        with open(auth_file, 'r') as auth_file_handle:
            try:
                tokens = json.load(auth_file_handle)
            except json.decoder.JSONDecodeError:
                tokens = {}
    else:
        tokens = {}

    if server in tokens and not refresh:
        return tokens[server]
    else:
        return _get_keycloak_token(username=username, password=password,
                                   auth_file=auth_file, server=server,
                                   realm_name=realm_name)
