from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import AuthenticationSerializer
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from .models import Trusted
from .serializers import ConfirmTrustedSerializer, CheckTrustedRequestSerializer
from rest_framework_simplejwt.tokens import RefreshToken


class AuthenticationView(APIView):
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # Для multipart данных

    def post(self, request, *args, **kwargs):
        # Печать данных запроса для дебага
        print(request.data)

        serializer = AuthenticationSerializer(data=request.data)

        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TrustedRequestsView(APIView):
    def get(self, request, *args, **kwargs):
        # Get the current user ID
        current_user = request.user

        # Find all Trusted records where the current user's ID is in the trusted field
        trusted_requests = Trusted.objects.filter(trusted=current_user)

        # Serialize the information we want to return
        trusted_data = []
        for trusted in trusted_requests:
            trusted_data.append({
                'user_id': trusted.user.id,
                'trusted_user_login': trusted.user.login,
                'status': trusted.status,
                'name': trusted.user.fio
            })

        # Return the response with the data
        return Response(trusted_data, status=status.HTTP_200_OK)

class ConfirmTrustedView(APIView):
    def post(self, request, *args, **kwargs):
        # Parse and validate the request data
        serializer = ConfirmTrustedSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['id']
            new_status = serializer.validated_data['status']

            # Get the current authenticated user
            current_user = request.user

            # Find the Trusted record where user = current_user and trusted = user_id
            try:
                trusted_instance = Trusted.objects.filter(trusted=current_user, user=user_id, status=0).order_by('-id').first()
            except Trusted.DoesNotExist:
                return Response({"error": "No trust record found for this user."}, status=status.HTTP_404_NOT_FOUND)

            # Update the status
            trusted_instance.status = new_status
            trusted_instance.save()

            # Return a success response
            return Response({"status": "ok", "new_status": new_status}, status=status.HTTP_200_OK)
        
        # If data is invalid, return the validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckTrustedRequestView(APIView):
    def post(self, request, *args, **kwargs):
        # Parse and validate the request data
        serializer = CheckTrustedRequestSerializer(data=request.data)
        if serializer.is_valid():
            secure_key = serializer.validated_data['secure_key']

            # Try to find the Trusted instance using the secure_key
            try:
                trusted_instance = Trusted.objects.get(secure_key=secure_key)
            except Trusted.DoesNotExist:
                return Response({"error": "No trust record found for this secure key."}, status=status.HTTP_404_NOT_FOUND)

            # Check the status of the trusted record
            if trusted_instance.status == 1:
                # User is authorized, so generate tokens
                user = trusted_instance.user  # Get the user associated with this trust record

                # Generate the access and refresh tokens for the user
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                # Return the tokens in the response
                return Response({
                    "status": "authorized",
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }, status=status.HTTP_200_OK)

            else:
                # If the status is not 1 (accepted), return an error message
                return Response({"error": "Trust request is not accepted."}, status=status.HTTP_400_BAD_REQUEST)
        
        # If data is invalid, return the validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)