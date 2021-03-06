from django.urls import include, path

from . import views

urlpatterns = [
    path('userList', views.MobileUserListView.as_view(),name="userlist"),
    path('createUser',views.createMobileUser.as_view(),name='createUser'),
    path('State',views.getStateList ,name='State'),
    path('District',views.getDistrictList,name='District'),
    path('Tehsil',views.getTehsilList,name='Tehsil'),
    path('Village',views.getVillageList,name='Village'),
    path('userStatus',views.userStatus,name='userStatus'),
    path('getDB',views.getDB,name='get'),
    path('OTP',views.OTP.as_view()),
    path('updateUser/<str:mobile>',views.updateMobileUser.as_view(),name='updateUser'),
]