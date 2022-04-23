import os
import re
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table
from rich import box
from dateutil import parser

from nglp_importer.models import CacheEntry

"""
Note: Analytics Dashboard can be figured out by using
https://github.com/NGLPteam/nglp-janeway-plugin
"""


def output_table_log(table_log):
    table = Table(title="Results", box=box.MINIMAL)
    table.add_column("Action")
    table.add_column("Status", justify="right", style="green")

    for row in table_log.keys():
        table.add_row(row, "✅" if table_log[row] else "[red]❌")

    console = Console()
    console.print(table)


def iso_date(date_value):
    dt = parser.parse(date_value)
    return dt.isoformat()


def concat(values, global_values):
    """
    Concatenates variables
    """
    output = None

    for variable in values:
        if variable in global_values.keys():
            # this flow just looks for straightforward variables
            if not output:
                output = global_values[variable]
            else:
                output += ', {}'.format(global_values[variable])
        else:
            # this does a regular expression match, uniting all fields
            # that match the pattern (e.g. advisor1, advisor2)
            for global_var in global_values.keys():
                match = re.match(variable, global_var)
                if match:
                    if not output:
                        output = global_values[match.group(0)]
                    else:
                        output += ', {}'.format(global_values[match.group(0)])

    return output


def parse_oa_status(value):
    # parse an OA status string into one of the options available
    # at https://github.com/NGLPteam/wdp-api/blob/main/lib/schemas/definitions/nglp/dissertation/1.0.0.json
    if value == 'openaccess':
        return 'open access'
    elif 'embargo' in value:
        return 'embargoed access'
    else:
        return 'open access'


def graph_ql_loader(schema, log=None, table_log=None):
    """
    Loads a GraphQL schema from the GraphQL directory
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))

    filename = schema + '.gql'

    graphql_file = Path(dir_path) / 'graphQL' / filename

    try:
        with open(graphql_file, 'r') as gql:
            if log:
                log.info('[green]Reading GQL:[/] {}'.format(graphql_file),
                              extra={'markup': True})

            if table_log is not None:
                table_log['Reading GQL {}'.format(graphql_file.name)] = True

            return gql.read()
    except OSError:
        if log:
            log.error('[red] Failed to read GQL:[/] {}'.format(graphql_file),
                      extra={'markup': True})

        if table_log is not None:
            table_log['Reading GQL {}'.format(graphql_file.name)] = False
        return ''


def _get_response(log, url, cache, cache_dir, stream=False):
    # get or create a cache entry
    # note that we do this whether caching is enabled or not
    c, created = CacheEntry.objects.get_or_create(url=url)
    if created:
        c.save()

    # grab a cache file if it exists
    cache_file = c.get_cache_file(log, cache_dir) if cache else None

    # see if there's a cached version
    if cache and cache_file:
        try:
            if not stream:
                with open(cache_file, 'r') as cached:
                    return cached.read(), c
            else:
                with open(cache_file, 'rb') as cached:
                    return cached.read(), c
        except OSError:
            log.error('[red]Unable to read from cache:[/] '
                      '{}'.format(cache_file),
                      extra={'markup': True})

    response = requests.get(url, stream=stream)

    # force UTF-8
    response.encoding = 'utf-8'

    if not response.status_code == 200:
        raise requests.RequestException

    return response, c


def get_remote_text(log, url, cache, cache_dir):
    response, c = _get_response(log, url, cache, cache_dir)

    # write the file to disk
    if hasattr(response, 'text'):
        with open(Path(cache_dir) / str(c.on_disk), 'w') as cached:
            cached.write(response.text)

        print(response.text)
        return response.text
    else:
        print(response)
        return response


def get_remote_binary(log, url, cache, cache_dir):
    response, c = _get_response(log, url, cache, cache_dir, stream=True)

    # write the file to disk
    if hasattr(response, 'raw'):
        bytes_obj = response.raw.read()

        with open(Path(cache_dir) / str(c.on_disk), 'wb') as cached:
            cached.write(bytes_obj)

        return bytes_obj
    else:
        return response
