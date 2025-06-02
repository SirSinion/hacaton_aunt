from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Trusted
import json
User = get_user_model()

import secrets
import string

# Function to generate a random secure string
def generate_secure_string(length=32):
    # Define the characters to use (letters and digits)
    characters = string.ascii_letters + string.digits
    # Generate a secure random string
    return ''.join(secrets.choice(characters) for _ in range(length))

class AuthenticationSerializer(serializers.Serializer):
    login = serializers.CharField(max_length=255)
    password = serializers.CharField(write_only=True, required=False)
    graphical = serializers.CharField(required=False)
    # serializers.ListField(
    #     child=serializers.ListField(child=serializers.IntegerField(), min_length=2, max_length=2)
    # )
    audio = serializers.CharField(required=False)
    trusted_account = serializers.BooleanField(required=False)

    def validate(self, data):
        login = data.get('login')
        password = data.get('password')
        graphical = data.get('graphical')
        trusted_account = data.get('trusted_account', False)

        # Проверка наличия пользователя
        try:
            user = User.objects.get(login=login)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist.")

        # Если указан trusted_account, пароль не требуется
        if trusted_account:
            password = None
            user1 = User.objects.get(login=login)
            user2 = user1.trusted_user
            secure_key = generate_secure_string(32)
            trusted = Trusted(user=user1, trusted=user2, secure_key=secure_key)
            trusted.save()
            return {'status': 'ok', 'secure_key': secure_key}
        else:
            # Проверка пароля
            if not check_password(password, user.password):
                raise serializers.ValidationError("Invalid password.")

        # Проверка графических координат с учётом разброса
        if graphical:
            if not self.validate_graphical_point(graphical, user.graphical):
                raise serializers.ValidationError("Graphical coordinates do not match.")

        # Генерация токенов
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Вернуть все поля
        return {
            'access_token': access_token,
            'refresh_token': str(refresh),
            'login': login,
            'graphical': graphical,
            'trusted_account': trusted_account
        }

    def validate_graphical_point(self, point, user_graphical):
        # Разброс в 1 точку
        threshold = 8
        point = json.loads(point)
        user_graphical = json.loads(user_graphical)

        if len(point) != len(user_graphical):
            return False
        
        for i in range(len(point)):
            x1 = point[i][0]
            y1 = point[i][1]
            x2 = user_graphical[i][0]
            y2 = user_graphical[i][1]

            if ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5 > threshold:
                return False
        return True
        
        
        # for i, p in enumerate(user_graphical):  # TODO сделать эйлерово расстояние, чтобы был круг
        #     for j, val in enumerate(p):
        #         # Если абсолютная разница между точками меньше или равна threshold
        #         if abs(val - point[i]) > threshold:
        #             return False
        # return True

class TrustedRequestSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    trusted_user_login = serializers.CharField(max_length=255)
    status = serializers.IntegerField()

class ConfirmTrustedSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    status = serializers.IntegerField(min_value=1, max_value=2)

class CheckTrustedRequestSerializer(serializers.Serializer):
    secure_key = serializers.CharField(max_length=256)