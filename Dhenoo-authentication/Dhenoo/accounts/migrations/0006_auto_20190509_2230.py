# Generated by Django 2.2.1 on 2019-05-09 17:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_auto_20190501_1218'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mobileuser',
            name='district',
            field=models.CharField(default='', max_length=20),
        ),
        migrations.AlterField(
            model_name='mobileuser',
            name='tehsil',
            field=models.CharField(default='', max_length=20),
        ),
        migrations.AlterField(
            model_name='mobileuser',
            name='village',
            field=models.CharField(default='', max_length=20),
        ),
    ]
