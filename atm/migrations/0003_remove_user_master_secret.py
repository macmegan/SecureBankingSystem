# Generated by Django 4.2.5 on 2024-03-26 08:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('atm', '0002_user_master_secret'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='master_secret',
        ),
    ]
