from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class CustomUserManager(BaseUserManager):
    def create_user(self, login, password=None, **extra_fields):
        """Создаёт обычного пользователя с login, password и дополнительными полями."""
        if not login:
            raise ValueError('Login должен быть указан')
        login = self.normalize_email(login)
        user = self.model(login=login, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, login, password=None, **extra_fields):
        """Создаёт суперпользователя."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(login, password, **extra_fields)

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

class CustomUser(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(max_length=255, unique=True)  # Логин
    password = models.CharField(max_length=255)  # Пароль
    graphical = models.CharField(max_length=255)  # Список координат точек
    audio = models.FileField(upload_to='user_audio/', blank=True, null=True)  # Аудиофайл
    trusted_user = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, blank=True, related_name='trusted_users_set')
    fio = models.CharField(max_length=255, null=True)

    is_active = models.BooleanField(default=True)  # Поле активности
    is_staff = models.BooleanField(default=False)  # Поле для админки

    objects = CustomUserManager()

    USERNAME_FIELD = 'login'  # Логин как поле для аутентификации
    REQUIRED_FIELDS = ['password']  # Только пароль

    def __str__(self):
        return self.login

class Trusted(models.Model):
    user = models.ForeignKey(CustomUser, related_name='trusted_user_set', on_delete=models.CASCADE)
    trusted = models.ForeignKey(CustomUser, related_name='trusted_by_set', on_delete=models.CASCADE)
    status = models.IntegerField(default=0)  # 0 - ожидание, 1 - принято, 2 - отказ
    secure_key = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.user_id} trusts {self.trusted_id}"