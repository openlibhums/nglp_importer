# NGLP Importer
A command-line system for importing BePress artifacts into the [NGLP](https://github.com/NGLPteam) [web-delivery platform](https://github.com/NGLPteam/wdp-api).

    Usage: python -m importer [OPTIONS] COMMAND [ARGS]...

    Options:
      --help  Show this message and exit.

    Commands:
      create-collection   Create a new collection on the WDP
      delete-collection   [WARNING] Destroy a collection on the WDP
      delete-item         [WARNING] Destroy an item on the WDP
      get-keycloak-token  Get an auth token from a keycloak server
      get-upload-token    Retrieve an upload token from the WDP
      get-user            Lookup a user by email or ORCID
      import-csv          Import a set of URLs from a CSV file
      import-single       Import a single item
      list-collections    List available community collections on the WDP
      list-items          List available community collection items on the WDP
      nuke-collection     [WARNING] Deletes all items in a collection
      test-authorisation  Test that authorisation is working on the WDP

Items marked [WARNING] are destructive. The client will not ask for confirmation before destructive operations.

## Configuration and Setup
Requirements should be installed using pip3 -r requirements.txt

Defaults in secrets.toml.default should be updated and then renamed to .secrets.toml.

To create the database, run manage.py migrate.

In Keycloak, you _must_ reset the password for every user on every realm and set the value to a non-temporary password. If you get "bad credentials" when trying to login, this is likely the problem.

## Requirements notes
This project uses:

* [Click](https://click.palletsprojects.com/en/8.0.x/) for CLI argument parsing
* [Dynaconf](https://www.dynaconf.com/) for configuration and secret passing
* [Django](https://www.djangoproject.com/) for the ORM and caching system
* [Requests](https://docs.python-requests.org/en/latest/) for remote fetch
* [Rich](https://github.com/Textualize/rich) for beautiful output
* [tuspy](https://tus-py-client.readthedocs.io/en/latest/) for TUS uploads
* [xmltodict](https://pypi.org/project/xmltodict/) for parsing XML into dictionaries

&copy; [Birkbeck, University of London](https://bbk.ac.uk/) and [Martin Paul Eve](https://eve.gd), 2022