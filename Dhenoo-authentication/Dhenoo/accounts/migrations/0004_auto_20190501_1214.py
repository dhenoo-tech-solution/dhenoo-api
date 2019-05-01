# Generated by Django 2.2 on 2019-05-01 06:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_mobileuser_daily_milk_production'),
    ]

    operations = [
        migrations.AddField(
            model_name='mobileuser',
            name='milk_type',
            field=models.CharField(default=None, max_length=20),
        ),
        migrations.AddField(
            model_name='mobileuser',
            name='number_animals',
            field=models.IntegerField(default=0),
        ),
    ]