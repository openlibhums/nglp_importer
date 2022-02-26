import uuid
from pathlib import Path

from django.db import models


class Contributor(models.Model):
    name = models.CharField(max_length=255)
    identifier = models.CharField(max_length=255)


class Subject(models.Model):
    name = models.CharField(max_length=255)


class Identifier(models.Model):
    identifier = models.CharField(max_length=255)


class Rights(models.Model):
    license = models.CharField(max_length=255)


class ETD(models.Model):
    """
    title = models.CharField(max_length=255)
    creator = models.ForeignKey(Contributor, on_delete=models.CASCADE)
    contributors = models.ManyToManyField(Contributor)
    subjects = models.ManyToManyField(Subject)
    date = models.DateTimeField()
    description = models.TextField()
    identifier = models.ManyToManyField(Identifier)
    rights = models.ForeignKey(Rights, on_delete=models.CASCADE)
    """

    @staticmethod
    def handle_spec(log, specification):
        handle_type = ['publication:etd', 'publication:etds',
                       'publication:cgu_etd']
        if specification in handle_type:
            log.info('[green]ETD handler:[/] selected',
                     extra={'markup': True})
            return True
        else:
            return False

    @staticmethod
    def parse(log, xml_dict):
        try:
            metadata = xml_dict['OAI-PMH']['GetRecord']['record']['metadata']
            xml_metadata = metadata['document-export']['documents']['document']
            log.info('[green]ETD handler:[/] extracted metadata block',
                     extra={'markup': True})

            return xml_metadata

        except KeyError:
            log.error(
                '[red]Error parsing ETD object. Expected key missing.[/]',
                extra={'markup': True})
        return None


class CacheEntry(models.Model):
    on_disk = models.UUIDField(primary_key=True, default=uuid.uuid4,
                               editable=False)
    url = models.URLField()

    def get_cache_file(self, log, cache_dir):
        try:
            file = Path(cache_dir) / str(self.on_disk)

            if file.is_file():
                log.info('[green]Cache hit:[/] {} ({})'.format(self.url,
                                                               file),
                         extra={'markup': True})
                return file
            else:
                raise CacheEntry.DoesNotExist
        except CacheEntry.DoesNotExist:
            log.error('[gray]Cache miss:[/] {}'.format(self.url),
                      extra={'markup': True})
            return None
