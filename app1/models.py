from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, name, password: None):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(email=self.normalize_email(email), name=name)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, name, password=None):
        user = self.create_user(email,name, password)
        user.is_admin = True
        user.save()
        return user


class CustomUser(AbstractBaseUser):
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255, null=False, blank=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    group = models.ForeignKey('Groups', on_delete=models.CASCADE, null=True, blank=True)
    group_rule = models.CharField(
        choices=[('owner', 'owner'), ('normal', 'normal')],
        default='normal',
        max_length=10
    )

    objects = UserManager()
    USERNAME_FIELD = 'email'


class Groups(models.Model):
    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=255)
    connections = models.ManyToManyField('Groups', blank=True)


class Request(models.Model):
    userId = models.IntegerField()
    groupId = models.IntegerField()
    date = models.DateTimeField(auto_now_add=True)

class ConnectionRequest(models.Model):
    groupId = models.IntegerField()
    date = models.DateTimeField(auto_now_add=True)
    from_group_id = models.IntegerField(default=None)


class Chats(models.Model):
    from_user = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='from_user', default=0)
    to_user = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='to_user', default=0)
    message = models.TextField()
    date = models.DateTimeField(auto_now_add=True)

