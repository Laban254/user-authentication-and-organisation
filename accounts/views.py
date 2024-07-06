from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.db import DatabaseError
from .models import User, Organisation
from .serializers import (
    UserSerializer, OrganisationSerializer, OrganisationCreateSerializer,
    RegistrationSerializer, LoginSerializer, AddUserToOrganisationSerializer
)
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import LoginSerializer
from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import ValidationError as DRFValidationError
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.permissions import IsAuthenticated

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
        try:
            serializer.is_valid(raise_exception=True)
            user = authenticate(email=serializer.validated_data['email'], password=serializer.validated_data['password'])

            if not user:
                return Response({
                    'status': 'Unauthorized',
                    'message': 'Authentication failed',
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
                        'lastName': user.lastName
                    }
                }
            }, status=status.HTTP_200_OK)
        
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
    
class UserDetailView(GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(user)
        return Response({
            "status": "success",
            "message": "User record retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

class OrganisationListView(GenericAPIView):
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        organisations = request.user.organisations.all()
        serializer = self.get_serializer(organisations, many=True)
        return Response({
            "status": "success",
            "message": "Organisations retrieved successfully",
            "data": {"organisations": serializer.data}
        }, status=status.HTTP_200_OK)

class OrganisationDetailView(GenericAPIView):
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, orgId, *args, **kwargs):
        try:
            organisation = Organisation.objects.get(pk=orgId, users=request.user)
        except Organisation.DoesNotExist:
            return Response({
                "status": "Bad Request",
                "message": "client error",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(organisation)
        return Response({
            "status": "success",
            "message": "Organisation record retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    

class OrganisationCreateView(GenericAPIView):
    serializer_class = OrganisationCreateSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data

            # Perform database operation directly in the view
            organisation = Organisation.objects.create(
                name=validated_data['name'],
                description=validated_data.get('description', '')
            )
            organisation.users.add(request.user)

            return Response({
                "status": "success",
                "message": "Organisation created successfully",
                "data": {
                    "orgId": organisation.org_id,  # Adjust based on your actual field name
                    "name": organisation.name,
                    "description": organisation.description
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
                "status": "Bad Request",
                "message": "Client error",
                "errors": errors
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        except DjangoValidationError as exc:
            return Response({
                "status": "Bad Request",
                "message": "Validation error occurred",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)

        except DatabaseError as exc:
            return Response({
                "status": "Bad Request",
                "message": "Database error occurred during organisation creation. Please try again later.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as exc:
            return Response({
                "status": "Bad Request",
                "message": "An unexpected error occurred during organisation creation. Please try again later.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)

class AddUserToOrganisationView(GenericAPIView):
    serializer_class = AddUserToOrganisationSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, orgId, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data

            try:
                organisation = Organisation.objects.get(pk=orgId, users=request.user)
            except Organisation.DoesNotExist:
                return Response({
                    "status": "Not Found",
                    "message": "Organisation not found",
                    "statusCode": 404
                }, status=status.HTTP_404_NOT_FOUND)

            try:
                user = User.objects.get(pk=validated_data['userId'])
            except User.DoesNotExist:
                return Response({
                    "status": "Not Found",
                    "message": "User not found",
                    "statusCode": 404
                }, status=status.HTTP_404_NOT_FOUND)

            organisation.users.add(user)

            return Response({
                "status": "success",
                "message": "User added to organisation successfully"
            }, status=status.HTTP_200_OK)
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
                "message": "Validation error occurred",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as exc:
            return Response({
                "status": "Bad request",
                "message": "Database error occurred during adding user to organisation. Please try again later.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            return Response({
                "status": "Bad request",
                "message": "An unexpected error occurred during adding user to organisation. Please try again later.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)