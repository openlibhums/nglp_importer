import csv
import inspect
import json
import logging
import os.path
import re
import sys
from collections import OrderedDict
from pathlib import Path

import click
import keycloak
import requests
import xmltodict
from keycloak import KeycloakOpenID
from rich import pretty
from rich.logging import RichHandler

import auth

from config import settings


sys.path.append(os.path.dirname(
    os.path.abspath(inspect.getfile(inspect.currentframe()))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nglp_importer.settings')

import django
django.setup()

from nglp_importer.models import CacheEntry, ETD
import utils
import wdp
from utils import output_table_log
from wdp import WebDeliveryPlatform

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)


@click.group()
def cli():
    pass


@click.command()
@click.option('--csv-filename',
              prompt='CSV file',
              help='The CSV file to read')
@click.option('--cache-dir',
              help='A cache directory',
              default=os.path.join(Path.home(), 'phcache'))
@click.option('--out-file',
              help='An output file',
              default=os.path.join(Path.home(), 'out.json'))
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--collection',
              prompt='Collection name',
              help='The collection name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--cache/--no-cache',
              help='Whether to cache or not',
              default=True)
@click.option('--commit/--no-commit',
              help='Whether to push to the WDP or not',
              default=True)
@click.option('--files/--no-files',
              help='Whether to push files to the WDP or not',
              default=True)
@click.option('--realm-name',
              help='The realm name',
              default="arizona")
def import_csv(csv_filename, cache_dir, out_file, username, password,
               community, collection, server, cache, commit, files, realm_name):
    """
    Import a set of URLs from a CSV file
    """
    username = username if username else settings.username
    password = password if password else settings.password

    # The CSV file requires a column called "URL" to be present
    with open(csv_filename, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            _import_single(row['URL'], cache_dir, out_file, username, password,
                           community, collection, server, cache, commit, files,
                           realm_name=realm_name)


@click.command()
@click.option('--url',
              prompt='URL',
              help='The URL to fetch')
@click.option('--cache-dir',
              help='A cache directory',
              default=os.path.join(Path.home(), 'phcache'))
@click.option('--out-file',
              help='An output file',
              default=os.path.join(Path.home(), 'out.json'))
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--collection',
              prompt='Collection name',
              help='The collection name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--cache/--no-cache',
              help='Whether to cache or not',
              default=True)
@click.option('--commit/--no-commit',
              help='Whether to push to the WDP or not',
              default=True)
@click.option('--files/--no-files',
              help='Whether to push files to the WDP or not',
              default=True)
@click.option('--realm-name',
              help='The realm name',
              default="arizona")
def import_single(url, cache_dir, out_file, username, password, community,
                  collection, server, cache, commit, files, realm_name):
    """
    Import a single item
    """
    username = username if username else settings.username
    password = password if password else settings.password

    _import_single(url, cache_dir, out_file, username, password, community,
                   collection, server, cache, commit, files, realm_name)


def _import_single(url, cache_dir, out_file, username, password, community,
                   collection, server, cache, commit, files, realm_name):
    """
    The non-Click version of the import func
    """
    log = logging.getLogger("rich")
    table_log = OrderedDict()

    # set up the cache dir
    if cache:
        setup_cache(log, cache_dir)
        table_log['Setup cache'] = True

    # set up the object parsers
    handlers = setup_handlers(log)
    table_log['Setup handlers'] = True

    # append a trailing slash to the URL if it is missing
    if not url.endswith('/'):
        url = url + '/'

    # build the DC URL identifier
    oai_dc_url, stat_url = build_urls(log=log, url=url, cache=cache,
                                      cache_dir=cache_dir)
    if not oai_dc_url:
        table_log['Build XML URL'] = False
        return
    else:
        table_log['Build XML URL'] = True

    # grab the XML
    oai_dc_xml = utils.get_remote_text(log=log, url=oai_dc_url, cache=cache,
                                       cache_dir=cache_dir)
    table_log['Get remote XML'] = True

    # parse into a dictionary
    dict_version = xmltodict.parse(oai_dc_xml, process_namespaces=False)
    table_log['Parse remote XML to dictionary'] = True

    # select a relevant parser/handler
    handler = get_handler(log=log, handlers=handlers, xml_dict=dict_version)

    if handler:
        # send the XML to the handler
        parsed = handler.parse(log=log, xml_dict=dict_version)

        try:
            with open(out_file, 'w') as output:
                # dump output to the file in JSON format
                output.write(json.dumps(parsed))
                log.info(
                    '[green]Data written to out file:[/] {}'.format(out_file),
                    extra={'markup': True})
                table_log['Handle remote XML'] = True

        except OSError:
            log.error(
                '[red]Unable to write to out file: [/]{}'.format(out_file),
                extra={'markup': True})
            table_log['Write to output file'] = False
    else:
        log.error(
            '[red]Unable to find a valid handler[/]'.format(),
            extra={'markup': True})
        table_log['Handle remote XML'] = False
        return

    # parse stats
    if stat_url:
        stat_text = utils.get_remote_text(log=log, url=stat_url, cache=cache,
                                          cache_dir=cache_dir)

        """
        This creates a dictionary with the following keys:
        downloads_this_year
        article_label
        total_downloads
        """
        stat_json = json.loads(stat_text)
        log.info(
            '[green]Got stat:[/] {} downloads '
            'this year'.format(stat_json['downloads_this_year']),
            extra={'markup': True})
        log.info(
            '[green]Got stat:[/] {} total '
            'downloads'.format(stat_json['total_downloads']),
            extra={'markup': True})

    wdp.create_etd(username, password, community, collection,
                   server, parsed, table_log=table_log, commit=commit,
                   cache_dir=cache_dir, files=files, realm_name=realm_name)


def get_handler(log, handlers, xml_dict):
    # extract the list of specification types from the XML
    try:
        specs = xml_dict['OAI-PMH']['GetRecord']['record']['header']['setSpec']
        log.info('[green]Found spec:[/] {}'.format(specs),
                 extra={'markup': True})
    except KeyError:
        log.error('[red]Unable to find setSpec field to assign a handler[/]',
                  extra={'markup': True})
        return None

    # return the first capable handler
    for handler in handlers:
        for spec in specs:
            if handler.handle_spec(log, spec):
                return handler


def setup_handlers(log):

    log.info('[green]Configuring handlers[/]', extra={'markup': True})

    return [ETD]


def setup_cache(log, cache_dir):
    log.info('[green]Checking/creating cache dir:[/] {}'.format(cache_dir),
             extra={'markup': True})
    Path(cache_dir).mkdir(parents=True, exist_ok=True)


def build_urls(log, url, cache, cache_dir):
    """
    Builds an OAI BePress XML URL from a standard BePress URL
    :param log: the logging object
    :param url: the URL on which to operate
    :param cache: whether to use the read cache or not
    :param cache_dir: the cache directory
    :return: an OAI_DC URL or None
    """
    # the URL structure should look like this:
    # https://digitalcommons.fiu.edu/etd/3884/
    bepress_regex = \
        r'(?P<schema>https?://)?(?P<repo>.+?)/(?P<type>.+?)/(?P<id>\d+)/'
    match = re.match(bepress_regex, url)

    if match:
        # note that the ID that we get here is not correct
        # we must instead look inside the file for
        # viewcontent.cgi?article=(\d+)&
        repo = match.group('repo')
        obj_type = match.group('type')
        item_id = None

        try:

            text = utils.get_remote_text(log=log, url=url, cache=cache,
                                         cache_dir=cache_dir)

            id_match_regex = r'article=(?P<id>\d+)'
            matches = re.finditer(id_match_regex, text, re.MULTILINE)

            for matchNum, match in enumerate(matches, start=1):
                item_id = match.group('id')

            if not item_id:
                log.error('[red]Unable to parse ID[/]', extra={'markup': True})
                return None, None

            # ascertain if there is a stat url for this
            stat_regex = r'insertDownloads\((?P<stat_id>\d+)\)'

            matches = re.finditer(stat_regex, text, re.MULTILINE)
            stat_id = None

            for matchNum, match in enumerate(matches, start=1):
                stat_id = match.group('stat_id')
                break

            if stat_id:
                log.info('[green]Stat ID match:[/] {}'.format(stat_id),
                         extra={'markup': True})

        except requests.RequestException:
            log.error('[red]Unable to fetch URL:[/] {}'.format(url),
                      extra={'markup': True})
            return None, None

        log.info('[green]Parsed[/] {} {} from {}'.format(obj_type,
                                                         item_id,
                                                         repo),
                 extra={'markup': True})

        # reformat to an oai_dc URL
        oai_dc_url = 'https://{0}/do/oai/?verb=GetRecord&metadataPrefix=' \
                     'document-export&identifier=oai:' \
                     '{0}:{1}-{2}'.format(repo, obj_type, item_id)

        log.info('[green]OAI DC URL:[/] {}'.format(oai_dc_url),
                 extra={'markup': True})

        stat_url = 'https://{0}/do/api/site/stats/{1}/json'.format(
            repo, stat_id
        )

        log.info('[green]Stats URL:[/] {}'.format(stat_url),
                 extra={'markup': True})

        return oai_dc_url, stat_url

    else:
        log.error('[red]Unable to parse URL:[/] {}'.format(url),
                  extra={'markup': True})
        return None, None


if __name__ == '__main__':
    pretty.install()
    cli.add_command(import_single)
    cli.add_command(import_csv)
    cli.add_command(auth.get_keycloak_token)
    cli.add_command(wdp.test_authorisation)
    cli.add_command(wdp.create_collection)
    cli.add_command(wdp.list_collections)
    cli.add_command(wdp.list_items)
    cli.add_command(wdp.delete_item)
    cli.add_command(wdp.nuke_collection)
    cli.add_command(wdp.get_upload_token)
    cli.add_command(wdp.get_user)
    cli.add_command(wdp.delete_collection)
    cli()
