# Generated by Django 2.2 on 2019-05-01 06:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_auto_20190501_1214'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mobileuser',
            name='milk_type',
            field=models.CharField(max_length=20),
        ),
    ]
