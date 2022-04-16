import json
import logging
import os
import re
from collections import OrderedDict
from io import BytesIO
from pathlib import Path

import click
import requests
import shutil

from tusclient import client

import auth
import utils
from utils import output_table_log

from config import settings


class GraphQLClientRequests:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.token = None
        self.headername = None

    def execute(self, query, variables=None):
        return self._send(query, variables)

    def inject_token(self, token, headername='Authorization'):
        self.token = 'Bearer ' + token
        self.headername = headername

    def _send(self, query, variables):
        data = {'query': query,
                'variables': variables}
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}

        if self.token is not None:
            headers[self.headername] = '{}'.format(self.token)

        req = requests.post(self.endpoint,
                            data=json.dumps(data).encode('utf-8'),
                            headers=headers)

        try:
            response = req.content.decode('utf-8')
            return response
        except requests.exceptions.RequestException as e:
            raise e


class WebDeliveryPlatform:
    base_endpoint = 'https://api.{0}.nglp.org/'
    endpoint = base_endpoint + 'graphql'
    files_endpoint = base_endpoint + 'files/'
    auth_endpoint = 'https://auth.nglp.org/auth/'
    realm_suffix = '-nglp'
    community = None
    community_name = ''
    log = logging.getLogger("rich")
    username = None
    password = None
    table_log = None
    slug = None

    def __init__(self, username, password, endpoint=None, community=None,
                 auth_endpoint=None, table_log=None, realm_name=None):
        self.base_endpoint = self.base_endpoint.format(realm_name)
        self.endpoint = endpoint if endpoint else self.endpoint
        self.endpoint = self.endpoint.format(realm_name)
        self.community_name = community
        self.auth_endpoint = auth_endpoint if auth_endpoint \
            else self.auth_endpoint
        self.table_log = table_log if table_log is not None else self.table_log
        self.username = username
        self.password = password
        self.realm_name = realm_name + self.realm_suffix

    def _send_query(self, query, refresh_token=False):
        # retrieve an access token
        token = self._get_access_token(refresh=refresh_token,
                                       realm_name=self.realm_name)

        # no token found
        if not token:
            if self.table_log is not None:
                self.table_log['Retrieved auth token'] = False

            self.log.error(
                '[red]Unable to retrieve auth token [/]',
                extra={'markup': True})
            return None

        gql = GraphQLClientRequests(endpoint=self.endpoint)
        gql.inject_token(token)
        response = json.loads(gql.execute(query=query))

        if 'errors' in response:
            self.log.error(
                '[red]Error encountered in remote: [/]{}'.format(
                    response['errors'][0]['message']),
                extra={'markup': True})

            if 'You are not authorized' in response['errors'][0]['message']:
                if self.table_log is not None:
                    self.table_log['Account does not have permission'] = False

            if 'Expired' in response['errors'][0]['message'] \
                    and not refresh_token:
                if self.table_log is not None:
                    self.table_log['Auth token expired'] = False
                return self._send_query(query, refresh_token=True)

        else:
            if self.table_log is not None:
                self.table_log['Retrieved auth token'] = True

        return response

    def check_auth(self):
        query = utils.graph_ql_loader(schema='viewer_query',
                                      log=self.log, table_log=self.table_log)

        return self._send_query(query=query)

    def list_collections(self):
        if not self._map_slug():
            return None

        query = utils.graph_ql_loader(schema='list_collections_query',
                                      log=self.log, table_log=self.table_log)
        query = query.format(self.slug)

        return self._send_query(query=query)

    def get_collection(self, collection_name):
        if not self._map_slug():
            return None

        query = utils.graph_ql_loader(schema='community_query',
                                      log=self.log, table_log=self.table_log)

        query = query.format(self.slug)

        result = self._send_query(query=query)

        if result and 'data' in result and 'community' in result['data']:
            for collection in \
                    result['data']['community']['collections']['edges']:
                if collection['node']['title'] == collection_name:
                    self.log.info(
                        '[green]Found collection:[/] '
                        '{}'.format(collection_name),
                        extra={'markup': True})
                    if self.table_log is not None:
                        self.table_log['Get collection ID'] = True
                    return collection['node']

        if self.table_log is not None:
            self.table_log['Get collection ID'] = False

        return None

    def _map_slug(self):
        if self.community is not None:
            return self.slug

        # gathers a slug for the current community
        query = utils.graph_ql_loader(schema='list_communities_query',
                                      log=self.log, table_log=self.table_log)

        result = self._send_query(query=query)

        if 'data' not in result and 'communities' not in result['data']:
            self.log.error(
                '[red]Unable to read slug mapping response[/]',
                extra={'markup': True})
            if self.table_log is not None:
                self.table_log['Mapping community to slug'] = False
            return None

        for community in result['data']['communities']['edges']:
            if community['node']['name'] == self.community_name:
                self.slug = community['node']['slug']
                self.community = community['node']['id']
                self.log.info(
                    '[green]Found slug:[/] {}'.format(self.slug),
                    extra={'markup': True})

                if self.table_log is not None:
                    self.table_log['Mapping community to slug'] = True

                return self.slug

        self.log.error(
            '[red]Unable to find a slug for this community[/]',
            extra={'markup': True})

        if self.table_log is not None:
            self.table_log['Mapping community to slug'] = False

    def create_collection(self, collection):
        # retrieve community if not already done
        self._map_slug()

        query = utils.graph_ql_loader(schema='create_collection_mutation',
                                      log=self.log, table_log=self.table_log)

        query = query.format(self.community, collection)

        return self._send_query(query=query)

    def list_items(self, collection, collection_object=None):
        # retrieve community if not already done
        self._map_slug()

        if not collection_object:
            # get the collection
            collection = self.get_collection(collection_name=collection)

            if not collection:
                return None
        else:
            collection = collection_object

        query = utils.graph_ql_loader(schema='list_items_query',
                                      log=self.log, table_log=self.table_log)

        query = query.format(collection['slug'])

        return self._send_query(query=query)

    def destroy_item(self, etd_id):
        """
        Destroys an item. Warning: this function doesn't protect the user.
        """
        query = utils.graph_ql_loader(schema='destroy_item_mutation',
                                      log=self.log, table_log=self.table_log)
        query = query.format(etd_id)

        return self._send_query(query=query)

    def destroy_collection(self, collection_id):
        """
        Destroys a collection. Warning: this function doesn't protect the user.
        """
        query = utils.graph_ql_loader(schema='destroy_collection_mutation',
                                      log=self.log, table_log=self.table_log)
        query = query.format(collection_id)

        return self._send_query(query=query)

    def download_file(self, url, cache, cache_dir):
        local_filename = os.path.join(Path.home(), 'down.pdf')

        try:
            with BytesIO(utils.get_remote_binary(log=self.log, url=url,
                                                 cache=cache,
                                                 cache_dir=cache_dir)) as r:
                with open(local_filename, 'wb') as f:
                    shutil.copyfileobj(r, f)

                self.log.info('[green]Downloaded:[/] '
                              '{}'.format(url), extra={'markup': True})

                if self.table_log is not None:
                    self.table_log['Download file'] = True

                return local_filename
        except:
            self.log.error('[red]Failed to download file:[/] '
                           '{}'.format(url), extra={'markup': True})

            if self.table_log is not None:
                self.table_log['Download file'] = False
            return None

    def update_etd(self, etd_id, thesis):
        # retrieve community if not already done
        self._map_slug()

        # a list of fields to extract from Bepress metadata
        field_list = ['degree_name', 'award_month', 'degree_year',
                      r'advisor\d*', 'publication_date']

        # a placeholder list that will be populated with dynamic fields
        # like "advisor1"
        dynamic_fields = []

        # a list of field mappings that map variables onto the final
        # substitution values
        field_mappings = OrderedDict()
        field_mappings['degree_name'] = ['degree_name', 'level']
        field_mappings['award_month'] = 'award_month'
        field_mappings['degree_year'] = ['degree_year', 'publication_date']


        # fields listed here will not be considered required variables
        # this is a way of marking field mappings as only for intermediate
        # operations, like concat
        field_pops = ['award_month']

        # a list of function hooks to parse values
        function_hooks = OrderedDict()

        # post hooks: functions to fire after other processing
        post_hooks = OrderedDict()
        post_hooks['degree_year'] = utils.iso_date

        # concatenation hooks to merge values
        concat_hooks = OrderedDict()
        concat_hooks['advisor'] = [r'advisor\d*']
        concat_hooks['degree_year'] = ['award_month', 'degree_year']

        # document fields
        document_fields = OrderedDict()
        document_fields['oa-status'] = 'document-type'

        # document hooks
        document_hooks = OrderedDict()
        document_hooks['oa-status'] = utils.parse_oa_status

        # clear all globals
        for key in concat_hooks.keys():
            globals()[key] = ''

        for key in field_mappings.keys():
            globals()[key] = ''

        for key in document_fields.keys():
            globals()[key] = ''

        # clear dynamic regex fields
        pop_list = []

        for key_name in globals().keys():
            for field_match in field_list:
                match = re.match(field_match, key_name)
                if match:
                    pop_list.append(match.group(0))

        for popper in pop_list:
            globals().pop(popper)
            self.log.info('[green]Removed dynamic value:[/] '
                          '{}'.format([popper]),
                          extra={'markup': True})

        # parse document-level data
        for field in document_fields.keys():
            if field in document_hooks:
                # call the hooked function
                globals()[field] = \
                    document_hooks[field](thesis[document_fields[field]])
            else:
                # just assign the value
                globals()[field] = document_fields[field]

        # extract the necessary data fields from the thesis
        # we have to use globals here, which is a bit hacky, but lets us easily
        # maintain the above list of variables we want to extract from fields
        for field in thesis['fields']['field']:
            if field['@name'] in field_list:
                if field['@name'] in function_hooks:
                    # call the hooked function
                    globals()[field['@name']] = \
                        function_hooks[field['@name']](field['value'])
                else:
                    # just assign the value
                    globals()[field['@name']] = field['value']

                self.log.info('[green]Found value:[/] '
                              '{} ({})'.format(field['@name'],
                                               globals()[field['@name']]),
                              extra={'markup': True})

                if self.table_log is not None:
                    self.table_log['Obtained value '
                                   '{0}'.format(field['@name'])] = True
            else:
                # check for regular expressions
                for field_match in field_list:
                    match = re.match(field_match, field['@name'])
                    if match:
                        dynamic_fields.append(match.group(0))
                        globals()[match.group(0)] = field['value']
                        self.log.info('[green]Found value:[/] '
                                      '{} ({})'.format(match.group(0),
                                                       field['value']),
                                      extra={'markup': True})
                        if self.table_log is not None:
                            self.table_log['Obtained value '
                                           '{0}'.format(match.group(0))] = True

        # create a list of required variables
        required_variables = []

        # run the concat procedure
        for concat in concat_hooks.keys():
            globals()[concat] = utils.concat(concat_hooks[concat], globals())

            self.log.info('[green]Field concat:[/] '
                          '{} ({})'.format(concat,
                                           globals()[concat]),
                          extra={'markup': True})

            # add concat fields to required list
            if concat not in required_variables:
                required_variables.append(concat)

        # run the post hooks
        for hook in post_hooks.keys():
            # only run the hook if we have a value
            if globals()[hook] is not None and globals()[hook] != '':
                globals()[hook] = \
                    post_hooks[hook](globals()[hook])

        # here we iterate over the field mappings, setting up the variables
        # in globals() for the substitution below
        global_list = globals()

        for key in field_mappings.keys():
            if type(field_mappings[key]) is str:
                if field_mappings[key] not in required_variables:
                    if key not in field_pops:
                        required_variables.append(field_mappings[key])
                if key in global_list:
                    globals()[field_mappings[key]] = globals()[key]
            elif type(field_mappings[key]) is list:
                found = False

                for field_map in field_mappings[key]:
                    if field_map not in required_variables:
                        required_variables.append(field_map)
                    if field_map in global_list and \
                            global_list[field_map] != '':
                        globals()[key] = globals()[field_map]
                        self.log.info('[green]Field map of {} success:[/] '
                                      '{}'.format(field_map,
                                                  globals()[key]),
                                      extra={'markup': True})
                        # exit the for loop on the first found variable
                        found = True
                        break

                if not found:
                    self.log.error('[red]Field map of {} failed:[/] '
                                   '{}'.format(key, field_mappings[key]),
                                   extra={'markup': True})

        global_list = globals()

        # check we have all the fields we require
        for variable in required_variables:
            if variable not in global_list:
                raise KeyError('Could not find variable {}'.format(variable))

        # finally, some manual extraction
        if 'authors' in thesis and 'institution' in thesis['authors']['author']:
            institution = thesis['authors']['author']['institution']
        else:
            institution = 'null'

        query = utils.graph_ql_loader('update_etd_mutation',
                                      log=self.log,
                                      table_log=self.table_log)

        if 'abstract' not in thesis:
            thesis['abstract'] = ''

        query = query.format(etd_id, thesis['abstract'],
                             global_list['degree_name'],
                             global_list['degree_year'],
                             global_list['advisor'],
                             institution,
                             global_list['oa-status'])

        return self._send_query(query=query)

    def attach_file(self, object_id, upload_id):
        """
        Attaches a file to an item
        """
        self._map_slug()

        query = utils.graph_ql_loader(schema='create_asset_mutation',
                                      log=self.log, table_log=self.table_log)
        query = query.format(object_id, upload_id)

        return self._send_query(query=query)

    def log_it(self, message):
        self.log.info('[green]TUS log:[/] '
                      '{}'.format(message),
                      extra={'markup': True})
        if self.table_log is not None:
            self.table_log[message] = True

    def get_user(self, email=None, orcid=None):
        if email is None and orcid is None:
            return None
        elif email:
            query = utils.graph_ql_loader('get_author_by_email', log=self.log,
                                          table_log=self.table_log)
            query = query.format(email)
        elif orcid:
            query = utils.graph_ql_loader('get_author_by_orcid', log=self.log,
                                          table_log=self.table_log)
            query = query.format(orcid)
        else:
            return None

        result = self._send_query(query=query)

        return result['data']['result']

    def affiliate_author(self, contribution_id, author_id):
        query = utils.graph_ql_loader('upsert_contributor_mutation',
                                      log=self.log,
                                      table_log=self.table_log)

        query = query.format(contribution_id, author_id)

        return self._send_query(query=query)

    def create_or_update_user(self, thesis, user=None):
        author = thesis['authors']['author']

        # finally, some manual extraction
        if 'institution' in author:
            institution = author['institution']
        else:
            institution = 'null'

        if not user:
            if 'email' in author:
                query = utils.graph_ql_loader('create_contributor_mutation',
                                              log=self.log,
                                              table_log=self.table_log)

                query = query.format(author['fname'], author['lname'],
                                     institution, author['email'])
            else:
                query = utils.graph_ql_loader('create_contributor_no_email_'
                                              'mutation',
                                              log=self.log,
                                              table_log=self.table_log)

                query = query.format(author['fname'], author['lname'],
                                     institution)
        else:
            query = utils.graph_ql_loader('update_contributor_mutation',
                                          log=self.log,
                                          table_log=self.table_log)

            query = query.format(author['fname'], author['lname'],
                                 institution, author['email'],
                                 user['id'])

        return self._send_query(query=query)

    def upload_file(self, filename):
        upload_token = self.get_upload_token()
        my_client = client.TusClient('https://api.staging.nglp.org/files/',
                                     headers={'Upload-Token': upload_token})

        uploader = my_client.uploader(filename, log_func=self.log_it)

        uploader.upload()

        # this returns a URL of the format
        # https://api.staging.nglp.org/files/5869717eb0c185a47f3cb8f0a99adb2d
        return uploader.url.rsplit('/', 1)

    def create_etd(self, collection_name, title):
        # retrieve community if not already done
        self._map_slug()

        # get the collection
        collection = self.get_collection(collection_name=collection_name)

        if not collection:
            return None

        # see if there's a thesis with this exact title already
        # if so, return this rather than creating a new duplicate
        result = self.list_items(collection=collection_name,
                                 collection_object=collection)

        thesis_object = None

        if result and 'data' in result and 'collection' in result['data']:
            for collection_result in \
                    result['data']['collection']['descendants']['edges']:
                if collection_result['node']['descendant']['title'] == title:
                    thesis_object = collection_result['node']['descendant']
                    self.log.info('[green]Found existing:[/] '
                                  '{} ({} / '
                                  '{})'.format(thesis_object['title'],
                                               thesis_object['id'],
                                               thesis_object['slug']),
                                  extra={'markup': True})
                    if self.table_log is not None:
                        self.table_log['Use existing thesis'] = True
                    break

        if thesis_object:
            return thesis_object

        query = utils.graph_ql_loader('create_etd_mutation', log=self.log,
                                      table_log=self.table_log)
        query = query.format(collection['id'], title)

        return self._send_query(query=query)

    def _map_community(self):
        """
        Maps the community string to the endpoint ID
        """

    def get_upload_token(self):
        try:
            query = utils.graph_ql_loader(schema='get_upload_token_query',
                                          log=self.log,
                                          table_log=self.table_log)

            result = self._send_query(query=query)

            if result and 'data' in result and 'viewer' in result['data']:
                return result['data']['viewer']['uploadToken']
            else:
                return None
        except:
            return None

    def _get_access_token(self, realm_name, refresh=False):
        token = auth.get_token(username=self.username, password=self.password,
                               server=self.auth_endpoint, refresh=refresh,
                               realm_name=realm_name)

        if token:
            return token['access_token']
        else:
            return None


def create_etd(username, password, realm_name, community, collection, server, thesis=None,
               table_log=None, commit=True, cache_dir=None, files=True):
    """
    Create an electronic thesis/dissertation on the WDP
    """
    log = logging.getLogger("rich")
    if table_log is None:
        table_log = OrderedDict()

    if not commit:
        log.info('[green]Not pushing to WDP[/]', extra={'markup': True})
    else:
        log.info('[green]Pushing to WDP[/]', extra={'markup': True})

    if table_log is not None:
        table_log['Pushing to WDP'] = commit

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)

    if commit:
        result = wdp.create_etd(collection_name=collection,
                                title=thesis['title'])
    else:
        result = {'id': 1337, 'title': thesis['title'], 'slug': 'sluggish'}

    object_id = None

    if result and 'data' in result and 'createItem' in result['data']:
        log.info('[green]Created thesis:[/] {}'.format(
            result['data']['createItem']['item']['slug']),
            extra={'markup': True})

        object_id = result['data']['createItem']['item']['id']

        if table_log is not None:
            table_log['Create new ETD'] = True

        if commit:
            wdp.update_etd(result['data']['createItem']['item']['id'], thesis)

    elif 'title' in result and result['title'] == thesis['title']:
        # we are using an existing thesis rather than newly created
        table_log['Locate existing ETD'] = True

        object_id = result['id']

        if commit:
            wdp.update_etd(result['id'], thesis)
    else:
        log.error(
            '[red]Unable to create new ETD[/]',
            extra={'markup': True})

        if table_log is not None:
            table_log['Create new ETD'] = False

        output_table_log(table_log)

        return

    if files:
        # download the file (goes to ~/down.pdf)
        filename = wdp.download_file(thesis['fulltext-url'], cache=True,
                                     cache_dir=cache_dir)

        if filename and commit:
            upload_result = wdp.upload_file(filename)

            log.info('[green]TUS file upload ID:[/] {}'.format(upload_result),
                     extra={'markup': True})

            if table_log is not None:
                table_log['Download PDF'] = True
                table_log['TUS file upload'] = True

            wdp.attach_file(object_id, upload_result[1])
        elif filename and not commit:
            log.info('[green]Skipping upload as in non-commit mode[/]',
                     extra={'markup': True})
            if table_log is not None:
                table_log['TUS file upload'] = False
                table_log['Download PDF'] = True
        else:
            log.error(
                '[red]Unable to download PDF[/]',
                extra={'markup': True})

            if table_log is not None:
                table_log['Download PDF'] = False
    else:
        log.info('[green]Skipping upload/download as in non-files mode[/]',
                 extra={'markup': True})
        if table_log is not None:
            table_log['File upload/download (set to skipped)'] = False

    has_email = True

    # attach creators to the document
    # first see if we have an email
    if 'email' in thesis['authors']['author']:
        user = wdp.get_user(email=thesis['authors']['author']['email'])
    else:
        user = None
        has_email = False
        log.error(
            '[red]Extracting author email from thesis[/]',
            extra={'markup': True})
        if table_log is not None:
            table_log['Extract author email'] = False

    if user:
        log.info('[green]Found existing user[/]',
                 extra={'markup': True})
        if table_log is not None:
            table_log['Found existing user'] = True
    else:
        log.info('[green]No existing user found[/]',
                 extra={'markup': True})
        if table_log is not None:
            table_log['Found existing user'] = False

    if commit:
        if not user:
            author_result = wdp.create_or_update_user(thesis=thesis)
        else:
            author_result = wdp.create_or_update_user(thesis=thesis, user=user)

        if has_email:
            # affiliate the author with the contribution
            user = wdp.get_user(email=thesis['authors']['author']['email'])

            if not user:
                # uh oh
                log.error(
                    '[red]Creating/updating user[/]',
                    extra={'markup': True})
                if table_log is not None:
                    table_log['Create/update user'] = False

                return
        else:
            user = \
                author_result['data']['createPersonContributor']['contributor']

        wdp.affiliate_author(contribution_id=object_id, author_id=user['id'])
    else:
        log.info('[green]Skipping create/update user as in non-commit mode[/]',
                 extra={'markup': True})
        if table_log is not None:
            table_log['Create/update user (set to skipped)'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def get_upload_token(username, password, community, server, realm_name):
    """
    Retrieve an upload token from the WDP
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)
    result = wdp.get_upload_token()

    if result:
        log.info('[green]Upload token:[/] {}'.format(result),
                 extra={'markup': True})
        if table_log is not None:
            table_log['Retrieved upload token'] = True
    else:
        log.error('[red]Failed to retrieve upload token[/]',
                  extra={'markup': True})
        if table_log is not None:
            table_log['Retrieved upload token'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--item',
              help='The item ID',
              prompt='Item ID to delete:')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def delete_item(username, password, community, server, item, realm_name):
    """
    Destroy an item on the WDP [WARNING]
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)
    result = wdp.destroy_item(item)

    if result and 'data' in result and 'destroyItem' in result['data']:
        if result['data']['destroyItem']['destroyed']:
            log.info('[green]Destroyed item[/]'.format(
                extra={'markup': True}))

            table_log['Destroyed item'] = True
        else:
            log.error(
                '[red]Unable to destroy item[/]',
                extra={'markup': True})
            table_log['Destroyed item'] = False
    else:
        log.error(
            '[red]Unable to destroy item[/]',
            extra={'markup': True})
        table_log['Destroyed item'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--collection',
              help='The collection name',
              prompt='Collection name to delete:')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def delete_collection(username, password, community, server, collection,
                      realm_name):
    """
    Destroy a collection on the WDP [WARNING]
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)

    collection_obj = wdp.get_collection(collection_name=collection)

    if collection_obj:
        result = wdp.destroy_collection(collection_obj['id'])

        if result and 'data' in result and 'destroyCollection' in result['data']:
            if result['data']['destroyCollection']['destroyed']:
                log.info('[green]Destroyed collection[/]'.format(
                    extra={'markup': True}))

                table_log['Destroyed collection'] = True
            else:
                log.error(
                    '[red]Unable to destroy collection[/]',
                    extra={'markup': True})
                table_log['Destroyed collection'] = False
        else:
            log.error(
                '[red]Unable to destroy collection[/]',
                extra={'markup': True})
            table_log['Destroyed collection'] = False
    else:
        log.error(
            '[red]Unable to destroy collection[/]',
            extra={'markup': True})
        table_log['Destroyed collection'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--collection',
              help='The collection name',
              prompt='Collection name')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def nuke_collection(username, password, community, collection, server,
                    realm_name):
    """
    Deletes all items in a collection [WARNING]
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)
    result = wdp.list_items(collection)

    if result and 'data' in result and 'collection' in result['data']:
        for collection in \
                result['data']['collection']['descendants']['edges']:
            log.info('[green]Found and deleting item:[/] {} ({})'.format(
                collection['node']['descendant']['title'],
                collection['node']['descendant']['id']),
                extra={'markup': True})
            wdp.destroy_item(collection['node']['descendant']['id'])

        table_log['Delete items'] = True
    else:
        log.error(
            '[red]Unable to delete items for this collection[/]',
            extra={'markup': True})

        if table_log is not None:
            table_log['Delete items'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--collection',
              help='The collection name',
              prompt='Collection name')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def list_items(username, password, community, collection, server, realm_name):
    """
    List available community collection items on the WDP
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)
    result = wdp.list_items(collection)

    if result and 'data' in result and 'collection' in result['data']:
        for collection in result['data']['collection']['descendants']['edges']:
            log.info('[green]Found item:[/] {} ({} / {})'.format(
                collection['node']['descendant']['title'],
                collection['node']['descendant']['id'],
                collection['node']['descendant']['slug']),
                extra={'markup': True})

        table_log['List items'] = True
    else:
        log.error(
            '[red]Unable to list items for this collection[/]',
            extra={'markup': True})

        if table_log is not None:
            table_log['List items'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def list_collections(username, password, community, server, realm_name):
    """
    List available community collections on the WDP
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              community=community, realm_name=realm_name)
    result = wdp.list_collections()

    if result and 'data' in result and 'community' in result['data']:
        for collection in result['data']['community']['collections']['edges']:
            log.info('[green]Found collection:[/] {} ({})'.format(
                collection['node']['title'], collection['node']['slug']),
                extra={'markup': True})

        table_log['List collections'] = True
    else:
        log.error(
            '[red]Unable to list collections for this community[/]',
            extra={'markup': True})

        if table_log is not None:
            table_log['List collections'] = False

    output_table_log(table_log)


@click.command()
@click.option('--collection',
              prompt='Collection name',
              help='The name of the new collection')
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--community',
              prompt='Community name',
              help='The community name')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def create_collection(collection, username, password, community, server,
                      realm_name):
    """
    Create a new collection on the WDP
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, community=community,
                              table_log=table_log, realm_name=realm_name)
    result = wdp.create_collection(collection)

    if result and 'data' in result and 'createCollection' in result['data'] \
            and 'id' in result['data']['createCollection']['collection']:
        log.info(
            '[green]Created collection:[/] {}'.format(
                result['data']['createCollection']['collection']['id']),
            extra={'markup': True})
        if table_log is not None:
            table_log['Created collection'] = True
    else:
        print(result)
        log.error(
            '[red]Unable to create collection[/]',
            extra={'markup': True})

        if table_log is not None:
            table_log['Created collection'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def test_authorisation(username, password, server, realm_name):
    """
    Test that authorisation is working on the WDP
    """

    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              realm_name=realm_name)
    result = wdp.check_auth()

    if result and 'data' in result and 'username' in result['data']['viewer']:
        log.info(
            '[green]Logged in as:[/] {}'.format(
                result['data']['viewer']['username']),
            extra={'markup': True})
        if table_log is not None:
            table_log['Retrieved logged in user'] = True
    else:
        log.error(
            '[red]Unable to retrieve logged-in info[/]',
            extra={'markup': True})

        if table_log is not None:
            table_log['Retrieved logged in user'] = False

    output_table_log(table_log)


@click.command()
@click.option('--username',
              default=None,
              help='The username to login with')
@click.option('--password',
              default=None,
              help='The password to login with')
@click.option('--server',
              help='The keycloak server',
              default='https://auth.nglp.org/auth/')
@click.option('--email',
              help='The email address to lookup')
@click.option('--orcid',
              help='The ORCID to lookup')
@click.option('--realm-name',
              help='The realm',
              default='arizona')
def get_user(username, password, server, email=None, orcid=None,
             realm_name=None):
    """
    Lookup a user by email or ORCID
    """
    username = username if username else settings.username
    password = password if password else settings.password

    log = logging.getLogger("rich")
    table_log = OrderedDict()

    wdp = WebDeliveryPlatform(username=username, password=password,
                              auth_endpoint=server, table_log=table_log,
                              realm_name=realm_name)
    result = wdp.get_user(email=email, orcid=orcid)

    if result:
        log.info(
            '[green]User:[/] {}'.format(
                result),
            extra={'markup': True})
    else:
        log.error(
            '[red]No user found[/]',
            extra={'markup': True})
