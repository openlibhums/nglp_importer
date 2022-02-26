# NGLP Importer
A command-line system for importing BePress artifacts into the [NGLP](https://github.com/NGLPteam) [web-delivery platform](https://github.com/NGLPteam/wdp-api).

    Usage: python -m importer [OPTIONS] COMMAND [ARGS]...

    Options:
      --help  Show this message and exit.

    Commands:
      create-collection   Create a new collection on the WDP
      delete-item         Destroy an item on the WDP [WARNING]
      get-keycloak-token  Get an auth token from a keycloak server
      get-upload-token    Retrieve an upload token from the WDP
      get-user            Lookup a user by email or ORCID
      import-csv          Import a set of URLs from a CSV file
      import-single       Import a single item
      list-collections    List available community collections on the WDP
      list-items          List available community collection items on the WDP
      nuke-collection     Deletes all items in a collection [WARNING]
      test-authorisation  Test that authorisation is working on the WDP

## Configuration and Setup
Requirements should be installed using pip3 -r requirements.txt

Defaults in secrets.toml.default should be updated and then renamed to .secrets.toml.

To create the database, run manage.py migrate.

&copy; Birkbeck, University of London and Martin Paul Eve, 2022