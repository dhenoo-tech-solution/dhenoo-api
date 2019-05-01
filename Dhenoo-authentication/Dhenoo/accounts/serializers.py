from rest_framework import serializers
from . import models

class MobileUserSerializer(serializers.ModelSerializer):

    
    class Meta:
        model = models.MobileUser
        fields = ('mobile','first_name','last_name','gender','dob','state','district','tehsil','village','daily_milk_production','daily_milk_production','milk_type','number_animals', )