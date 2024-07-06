from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.db import DatabaseError
from .models import User, Organisation
from .serializers import UserSerializer, RegistrationSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import LoginSerializer
from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import ValidationError as DRFValidationError
from django.core.exceptions import ValidationError as DjangoValidationError

class RegisterView(GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data

            user = User.objects.create_user(
                email=validated_data['email'],
                firstName=validated_data['firstName'],
                lastName=validated_data['lastName'],
                password=validated_data['password'],
                phone=validated_data.get('phone', '')
            )

            org_name = f"{user.firstName}'s Organisation"
            organisation = Organisation.objects.create(
                name=org_name,
                description=f"Organisation created for {user.firstName} {user.lastName}"
            )
            organisation.users.add(user)

            refresh = RefreshToken.for_user(user)

            return Response({
                "status": "success",
                "message": "Registration successful",
                "data": {
                    'accessToken': str(refresh.access_token),
                    "user": UserSerializer(user).data
                }
            }, status=status.HTTP_201_CREATED)
        except DRFValidationError as exc:
            errors = []
            for field, messages in exc.detail.items():
                for message in messages:
                    errors.append({
                        "field": field,
                        "message": message
                    })
            return Response({
                "errors": errors
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        except DjangoValidationError as exc:
            return Response({
                "status": "Bad request",
                # "message": "Validation error occurred",
                "message":"Registration unsuccessful",
                # "details": exc.messages,
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as exc:
            return Response({
                "status": "Bad request",
                # "message": "Database error occurred during registration. Please try again later.",
                # "details": str(exc),
                "message":"Registration unsuccessful",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            return Response({
                "status": "Bad request",
                # "message": "An unexpected error occurred during registration. Please try again later.",
                # "details": str(exc),
                "message":"Registration unsuccessful",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        
        
class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(email=serializer.validated_data['email'], password=serializer.validated_data['password'])

        if not user:
            return Response({
                'status': 'Unauthorized',
                'message': "Authentication failed",
                'statusCode': 401
            }, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        return Response({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'accessToken': str(refresh.access_token),
                'user': {
                    'userId': user.userId,
                    'email': user.email,
                    'firstName': user.firstName,
                    'lastName': user.lastName,
                }
            }
        }, status=status.HTTP_200_OK)