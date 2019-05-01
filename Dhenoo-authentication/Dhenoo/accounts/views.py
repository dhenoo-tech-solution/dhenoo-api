from rest_framework import generics,status
import pandas as pd
from .models import MobileUser
#from .serializers import UserSerializer
from django.views.generic import ListView, DetailView 
from django.views.generic.edit import CreateView, UpdateView, DeleteView
import http.client
from urllib.parse import urlencode
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response
from django.http import HttpResponse
import json
from django.http import JsonResponse
from django.forms.models import model_to_dict
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import MobileUserSerializer


data=pd.read_pickle('State_District_Tehsil_Village.pkl')

class MobileUserListView(generics.ListCreateAPIView):
    queryset = MobileUser.objects.all()
    serializer_class = MobileUserSerializer


class createMobileUser(generics.CreateAPIView):
    lookup_field='mobile'
    serializer_class=MobileUserSerializer
    #permission_classes = IsAuthenticated
    """ def get_queryset(self):
        return MobileUser.objects.all() """

class updateMobileUser(generics.RetrieveUpdateDestroyAPIView):
    lookup_field = 'mobile'
    serializer_class = MobileUserSerializer
    def get_queryset(self):
        return MobileUser.objects.all()

# Create your views here.
@api_view(['POST'])
@permission_classes((AllowAny,))
def generateOTP(request):
    json_data_response={}
    mobile=request.data.get("mobile")
    conn = http.client.HTTPConnection("control.msg91.com")
    payload = {'authkey':"271650AhgEeZi4lz5caca5e1",'message':"your otp is ##OTP##",'sender':"ABCDEF",'mobile':mobile}
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'x-csrf-token': "wWjeFkMcbopci1TK2cibZ2hczI",
    'cache-control': "no-cache",
    'postman-token': "23c09c76-3b030-eea1-e16ffd48e9"
    }
    conn.request("POST", "/api/sendotp.php?otp_length=&authkey=&message=&sender=&mobile=&otp=&email=&otp_expiry=&template=", urlencode(payload),headers)
    res = conn.getresponse()
    api_response = json.loads(res.read().decode("utf-8"))
    if api_response['type'] == 'success':
        json_data_response['status']=status.HTTP_200_OK
        json_data_response['message']=f"OTP succesfully sent on {mobile},Please enter OTP"
    else:
        json_data_response['status']=status.HTTP_400_BAD_REQUEST
        json_data_response['message']=api_response['message']
    json_data_response['payload']=None
    return JsonResponse(json_data_response)

@api_view(['POST'])
@permission_classes((AllowAny,))
def verifyOTP(request):
    json_data_response={}
    mobile=request.data.get("mobile")
    otp=request.data.get("otp")
    conn = http.client.HTTPSConnection("control.msg91.com")
    headers = { 'content-type': "application/x-www-form-urlencoded" }
    payload={
        'authkey':"271650AhgEeZi4lz5caca5e1",
        'mobile': mobile,
        'otp': otp
    }
    conn.request("POST", "/api/verifyRequestOTP.php?authkey=&mobile=&otp=", urlencode(payload), headers)
    res = conn.getresponse()
    api_response = json.loads(res.read().decode("utf-8"))
    if api_response['type'] == 'success':
        json_data_response['status']=status.HTTP_200_OK
        is_registered = MobileUser.objects.filter(mobile=mobile).exists()
        json_data_response['payload']={'is_registered' : is_registered}
        if is_registered:
            json_data_response['message']='OTP verified'
            user_data_json = model_to_dict( MobileUser.objects.get(mobile=mobile) )
            #we can have better logic for below statement
            user_data_json={key: user_data_json[key] for key in user_data_json if key not in ['id','password','last_login','active','staff','admin']}
            json_data_response['payload']['user_data'] = user_data_json
        else:
            json_data_response['message']='OTP verified,but user is not registered'
    else:
        json_data_response['status']=status.HTTP_401_UNAUTHORIZED
        json_data_response['message']=api_response['message']
        json_data_response['payload']=None
    return JsonResponse(json_data_response)

@api_view(['GET'])
@permission_classes((AllowAny,))
def getStateList(request):
    state_list=sorted(list(data['STATE NAME'].unique()))
    json_data_response={}
    json_data_response['status']=status.HTTP_200_OK
    json_data_response['message']="Please Select State"
    json_data_response['payload']={'State_list':state_list}
    return JsonResponse(json_data_response)

@api_view(['POST'])
@permission_classes((AllowAny,))
def getDistrictList(request):
    state=request.data.get("state")
    json_data_response={}
    district_list=sorted(list(data[data['STATE NAME']==state]['DISTRICT NAME'].unique()))
    if district_list:
        json_data_response['status']=status.HTTP_200_OK
        json_data_response['message']="Please Select District"
    else:
        json_data_response['status']=status.HTTP_204_NO_CONTENT
        json_data_response['message']="Please type valid state"
    json_data_response['payload']={'District_list':district_list}
    return JsonResponse(json_data_response)

@api_view(['POST'])
@permission_classes((AllowAny,))
def getTehsilList(request):
    district=request.data.get("district")
    tehsil_list=sorted(list(data[data['DISTRICT NAME']==district]['TEHSIL NAME'].unique()))
    json_data_response={}
    if tehsil_list:
        json_data_response['status']=status.HTTP_200_OK
        json_data_response['message']="Please Select Tehsil"
    else:
        json_data_response['status']=status.HTTP_204_NO_CONTENT
        json_data_response['message']="Please type valid district"
    json_data_response['payload']={'Tehsil_list':tehsil_list}
    return JsonResponse(json_data_response)


@api_view(['POST'])
@permission_classes((AllowAny,))
def getVillageList(request):
    tehsil=request.data.get("tehsil")
    village_list=sorted(list(data[data['TEHSIL NAME']==tehsil]['VILLAGE NAME'].unique()))
    json_data_response={}
    if village_list:
        json_data_response['status']=status.HTTP_200_OK
        json_data_response['message']="Please Select Village"
    else:
        json_data_response['status']=status.HTTP_204_NO_CONTENT
        json_data_response['message']="Please type valid tehsil"
    json_data_response['payload']={'village_list':village_list}
    return JsonResponse(json_data_response)

    