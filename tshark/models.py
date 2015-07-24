from django.db import models

# Create your models here.
class userflt(models.Model):
    name = models.CharField(max_length=100, blank=True, default='')

    def __unicode__(self):
        return self.name


