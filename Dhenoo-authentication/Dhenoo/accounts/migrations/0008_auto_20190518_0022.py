# Generated by Django 2.2.1 on 2019-05-17 18:52

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_mobileuser_otp_count'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mobileuser',
            name='last_login',
            field=models.DateTimeField(blank=True, default=datetime.datetime.now),
        ),
    ]