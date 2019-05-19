from rest_framework import generics,status
import pandas as pd
from datetime import datetime, timezone
from django.conf import settings
from .models import MobileUser
from rest_framework.views import APIView
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
import logging

logger = logging.getLogger('accounts')
data=pd.read_pickle('State_District_Tehsil_Village.pkl')
state_list=sorted(list(data['STATE NAME'].unique()))
logger.info("state_district_tehsil dataframe is ready for states {}".format(state_list))

class MobileUserListView(generics.ListCreateAPIView):
    queryset = MobileUser.objects.all()
    serializer_class = MobileUserSerializer


class createMobileUser(generics.CreateAPIView):
    try:
        serializer_class=MobileUserSerializer
        model = MobileUser
        queryset = MobileUser.objects.all()

        def create(self, request, *args, **kwargs):
            serializer = MobileUserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                logger.info("user created successfully : {}".format(serializer.data))
                return JsonResponse({'status':status.HTTP_201_CREATED,'message':'User created successfully','payload':serializer.data})
            logger.warning("user creation failed : {}".format(serializer.errors))
            return JsonResponse({'status':status.HTTP_400_BAD_REQUEST,'message':serializer.errors,'payload':None})
    except Exception as e:
        logger.error("createMobileUser API failed: {}".format(str(e)))


class updateMobileUser(generics.RetrieveUpdateDestroyAPIView):
    try:
        lookup_field = 'mobile'
        serializer_class = MobileUserSerializer
        def get_queryset(self):
            return MobileUser.objects.all()
        
        def retrieve(self, request, *args, **kwargs):
            try:
                instance = self.get_object()
                serializer = MobileUserSerializer(instance=instance)
                logger.info("get user detail : {}".format(serializer.data))
                return JsonResponse({'status':status.HTTP_200_OK,'message':'User detail','payload':serializer.data})
            except Exception as e:
                logger.warning("get user detail failed : {}".format(str(e)))
                return JsonResponse({'status':status.HTTP_404_NOT_FOUND,'message':str(e),'payload':None})
        
        def update(self, request, *args, **kwargs):
            instance = self.get_object()
            serializer = MobileUserSerializer(
                instance=instance,
                data=request.data
            )
            if serializer.is_valid():
                serializer.save()
                logger.info("user detail succesfully updated : {}".format(serializer.data))
                return JsonResponse({'status':status.HTTP_200_OK,'message':'User details updated successfully','payload':serializer.data})
            logger.warning("user updation failed : {}".format(serializer.errors))
            return JsonResponse({'status':status.HTTP_400_BAD_REQUEST,'message':serializer.errors,'payload':None})
    except Exception as e:
        logger.error("updateMobileUser API failed: {}".format(str(e)))



@api_view(['GET'])
@permission_classes((AllowAny,))
def getStateList(request):
    try:
        state_list=sorted(list(data['STATE NAME'].unique()))
        if state_list:
            return JsonResponse({'status':status.HTTP_200_OK,'message':"Please Select State",'payload':{'State_list':state_list} })
        logger.error('State list not updated,check dataframe')
        return JsonResponse({'status':status.HTTP_204_NO_CONTENT,'message':"Please try again",'payload':{'State_list':state_list} })
    except Exception as e:
        logger.error("getStateList API failed: {}".format(str(e)))

    

@api_view(['POST'])
@permission_classes((AllowAny,))
def getDistrictList(request):
    try:
        state=request.data.get("state")
        district_list=sorted(list(data[data['STATE NAME']==state]['DISTRICT NAME'].unique()))
        if district_list:
            return JsonResponse({'status':status.HTTP_200_OK,'message':"Please Select District",'payload':{'District_list':district_list} })
        logger.warning("pass valid state name to get district")
        return JsonResponse({'status':status.HTTP_204_NO_CONTENT,'message':"Please type valid state",'payload':{'District_list':district_list} })
    except Exception as e:
        logger.error("getDistrictList API failed: {}".format(str(e)))

@api_view(['POST'])
@permission_classes((AllowAny,))
def getTehsilList(request):
    try:
        district=request.data.get("district")
        tehsil_list=sorted(list(data[data['DISTRICT NAME']==district]['TEHSIL NAME'].unique()))
        if tehsil_list:
            return JsonResponse({'status':status.HTTP_200_OK,'message':"Please Select Tehsil",'payload':{'Tehsil_list':tehsil_list} })
        logger.warning("pass valid district name to get tehsil")
        return JsonResponse({'status':status.HTTP_204_NO_CONTENT,'message':"Please type valid district",'payload':{'Tehsil_list':tehsil_list} })
    except Exception as e:
        logger.error("getTehsilList API failed: {}".format(str(e)))


@api_view(['POST'])
@permission_classes((AllowAny,))
def getVillageList(request):
    try:
        tehsil=request.data.get("tehsil")
        village_list=sorted(list(data[data['TEHSIL NAME']==tehsil]['VILLAGE NAME'].unique()))
        if village_list:
            return JsonResponse({'status':status.HTTP_200_OK,'message':"Please Select Village",'payload':{'village_list':village_list} })
        logger.warning("pass valid tehsil name to get village")
        return JsonResponse({'status':status.HTTP_204_NO_CONTENT,'message':"Please type valid tehsil",'payload':{'village_list':village_list} })
    except Exception as e:
        logger.error("getVillageList API failed: {}".format(str(e)))






class OTP(APIView):
    def update_status(self,mobile,flag,mobile_info=None):
        obj=MobileUser.objects.get(mobile=mobile)
        print(mobile_info)
        if mobile_info:obj.mobile_info=mobile_info
        if obj.otp_count==3:
            if divmod((datetime.now().replace(tzinfo=None)-obj.last_login.replace(tzinfo=None)).seconds,60)[0] >60:
                obj.active=True
                obj.last_login=datetime.now()
                obj.otp_count=1
                obj.save()
                return True
            else:
                obj.active=False
                obj.save()
                return False
        if obj.otp_count < 3 and flag==False:
            obj.otp_count+=1
            obj.last_login=datetime.now()
            obj.save()
            return True
        obj.save()
        return True
    
    def post_verifyOTP(self,request):
        try:
            mobile=request.data.get("mobile")
            otp=request.data.get("otp")
            conn = http.client.HTTPSConnection("control.msg91.com")
            headers = { 'content-type': "application/x-www-form-urlencoded" }
            payload={
                'authkey':settings.AUTH_KEY,
                'mobile': mobile,
                'otp': otp
            }
            conn.request("POST", "/api/verifyRequestOTP.php?authkey=&mobile=&otp=", urlencode(payload), headers)
            res = conn.getresponse()
            api_response = json.loads(res.read().decode("utf-8"))
            if api_response['type'] == 'success':
                is_registered = MobileUser.objects.filter(mobile=mobile).exists()
                if is_registered:
                    user_data_json = model_to_dict( MobileUser.objects.get(mobile=mobile) )
                    #we can have better logic for below statement
                    user_data_json={key: user_data_json[key] for key in user_data_json if key not in ['id','password','last_login','active','staff','admin']}
                    logger.info("OTP succesfully verified and user exist: {}".format(mobile))
                    return JsonResponse({'status':status.HTTP_200_OK,'message':"OTP verified",'payload':{'is_registered' : is_registered,'user_data':user_data_json} })
                logger.info("OTP succesfully verified,but user does not exist : {}".format(mobile))
                return JsonResponse({'status':status.HTTP_200_OK,'message':"OTP verified,but user is not registered",'payload':{'is_registered' : is_registered,'user_data':None} })
            logger.warning("OTP verification failed : {},{}".format(mobile,api_response['message']))
            self.update_status(mobile,False)
            return JsonResponse({'status':status.HTTP_401_UNAUTHORIZED,'message':api_response['message'],'payload':None })
        except Exception as e:
            logger.error("VerifyOTP API failed: {}".format(str(e)))
    
  
    def post_generateOTP(self,request):
        try:
            mobile=request.data.get("mobile")
            mobile_info=request.data.get("mobile_info")
            print(mobile_info,'asa')
            if self.update_status(mobile,True,mobile_info):
                conn = http.client.HTTPConnection("control.msg91.com")
                payload = {'authkey':settings.AUTH_KEY,'message':"your otp is ##OTP##",'sender':"ABCDEF",'mobile':mobile}
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
                    logger.info("OTP succesfully sent : {}".format(mobile))
                    return JsonResponse({'status':status.HTTP_200_OK,'message':"OTP succesfully sent on {},Please enter OTP".format(mobile),'payload':None })
                logger.warning("OTP generation failed : {}".format(api_response['message']))
                return JsonResponse({'status':status.HTTP_400_BAD_REQUEST,'message':api_response['message'],'payload':None })
            return JsonResponse({'status':status.HTTP_400_BAD_REQUEST,'message':'Please try after 1 hour','payload':None })
        except Exception as e:
            logger.error("generate OTP API failed: {}".format(str(e)))
    
    def post(self,request):
        if request.data.get("otp"):
            return self.post_verifyOTP(request)
        else:
            return self.post_generateOTP(request)

@api_view(['POST'])
@permission_classes((AllowAny,))
def userStatus(request):
    try:
        mobile=request.data.get("mobile")
        return JsonResponse({'status':status.HTTP_204_NO_CONTENT,'message':MobileUser.objects.filter(mobile=mobile).exists(),'payload':None })
    except Exception as e:
        logger.error("userStatus API failed: {}".format(str(e)))

    

@api_view(['POST'])
@permission_classes((AllowAny,))       
def getDB(request):
    obj=MobileUser.objects.get(mobile=request.data.get("mobile"))
    print(MobileUser.objects.get(mobile=request.data.get("mobile")))
    print(obj)
    print(obj.active)
    return HttpResponse([obj.mobile,obj.otp_count,obj.active,obj.last_login])