from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)

class MobileUserManager(BaseUserManager):
    def create_user(self, mobile, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        if not mobile:
            raise ValueError('Users must have an mobile number')

        user = self.model(
            mobile=mobile,

        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    '''
    Not using for time being
    def create_staffuser(self, email, password):
        """
        Creates and saves a staff user with the given email and password.
        """
        user = self.create_user(
            email,
            password=password,
        )
        user.staff = True
        user.save(using=self._db)
        return user
    '''
    def create_superuser(self, mobile,password):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(
            mobile,
            password=password,
        )
        user.staff = True
        user.admin = True
        user.save(using=self._db)
        return user
    

class MobileUser(AbstractBaseUser):
    #name = models.CharField(max_length=50)
    #otp = models.CharField(max_length=4,default="0000")
    mobile = models.CharField(unique=True, max_length=15)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    gender = models.CharField(null=True,blank=True,max_length=1, choices=(
        ('M', 'Male'),
        ('F', 'Female'),
    ))
    dob = models.DateField(null=True, blank=True)
    state = models.CharField(max_length=20)
    district = models.CharField(max_length=20,default=None)
    tehsil= models.CharField(max_length=20,default=None)
    village = models.CharField(max_length=20,default=None)
    daily_milk_production=models.IntegerField(default=0)
    milk_type=models.CharField(max_length=20)
    number_animals=models.IntegerField(default=0)
    active = models.BooleanField(default=True)
    staff = models.BooleanField(default=False) # a admin user; non super-user
    admin = models.BooleanField(default=False) # a superuser
    # notice the absence of a "Password field", that's built in.

    USERNAME_FIELD = 'mobile'
    REQUIRED_FIELDS = [] # Email & Password are required by default.
    objects = MobileUserManager()

    def get_full_name(self):
        # The user is identified by their email address
        return self.mobile

    def get_short_name(self):
        # The user is identified by their email address
        return self.mobile

    def __str__(self):              # __unicode__ on Python 2
        return self.mobile

    def has_perm(self, perm, obj=None):
        #"Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        #"Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        #"Is the user a member of staff?"
        return self.staff

    @property
    def is_admin(self):
        #"Is the user a admin member?"
        return self.admin

    @property
    def is_active(self):
        #"Is the user active?"
        return self.active

