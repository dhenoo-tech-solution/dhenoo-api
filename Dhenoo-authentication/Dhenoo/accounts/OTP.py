import http
from django.conf import settings
import logging
from urllib.parse import urlencode
import json
import _pickle as cPickle
from accounts.models import MobileUser

class OTP():
    def __init__(self,mobile,filename="OTP_Checks.pickle"):
        self.mobile=mobile
        self.count=0
        self.filename = filename
    
    def save(self):
        f = open(self.filename, 'wb')
        cPickle.dump({self.mobile:self.count}, f)
        f.close
    
    def read(self):
        f = open(self.filename, 'rb')
        obj=cPickle.load(f)
        print(obj)
        #print(cPickle.load(f).mobile)
        #print(obj.mobile)
        f.close
        return obj
        
        #print(f)

    
    def generateOTP(self):
        print(self.read()['count'])
        print(self.read()['mobile'])
        if self.read()['mobile']==self.mobile:
            if self.read()['count'] < 4:
                print(self.count)
                self.count+=1
                self.save()
            else:
                print('count excedded',self.count)
        """conn = http.client.HTTPConnection("control.msg91.com")
            payload = {'authkey':settings.AUTH_KEY,'message':"your otp is ##OTP##",'sender':"ABCDEF",'mobile':self.mobile}
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'x-csrf-token': "wWjeFkMcbopci1TK2cibZ2hczI",
            'cache-control': "no-cache",
            'postman-token': "23c09c76-3b030-eea1-e16ffd48e9"
            }
            conn.request("POST", "/api/sendotp.php?otp_length=&authkey=&message=&sender=&mobile=&otp=&email=&otp_expiry=&template=", urlencode(payload),headers)
            res = conn.getresponse()
            api_response = json.loads(res.read().decode("utf-8"))
            return api_response"""
           
    def msg91APIconn(self,mobile):
        conn = http.client.HTTPConnection("control.msg91.com")
        payload = {'authkey':settings.AUTH_KEY,'message':"your otp is ##OTP##",'sender':"ABCDEF",'mobile':mobile}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'x-csrf-token': "wWjeFkMcbopci1TK2cibZ2hczI",
            'cache-control': "no-cache",
            'postman-token': "23c09c76-3b030-eea1-e16ffd48e9"
            }

    def updateDB(self,mobile):
        print('in update')
        obj=MobileUser.objects.get(mobile=mobile)
        if obj.otp_count < 3:
            print(obj.otp_count)
            obj.otp_count+=1
        else:
            print(obj.otp_count)
            obj.otp_count=0
            obj.active=False
        obj.save()
        return obj
        
    def getDB(self):
        obj=MobileUser.objects.get(mobile=self.mobile)
        print(obj)







