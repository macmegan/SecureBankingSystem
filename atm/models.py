from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    password = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    balance = models.DecimalField(max_digits=10, decimal_places=2)

    USERNAME_FIELD = 'username'

    def __str__(self):
        return self.username
