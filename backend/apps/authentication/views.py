from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import update_session_auth_hash, authenticate
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import LoginSerializer, UserSerializer, RegisterSerializer, ChangePasswordSerializer
from .models import CustomUser
from django.db import connection
from django.db.utils import DatabaseError
from bson import ObjectId
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@swagger_auto_schema(
    method='post',
    request_body=LoginSerializer,
    responses={
        200: openapi.Response(
            description="Login successful",
            examples={
                "application/json": {
                    "user": {
                        "id": "507f1f77bcf86cd799439011",
                        "username": "john_doe",
                        "email": "john@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "role": "analyst"
                    },
                    "tokens": {
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
                    }
                }
            }
        ),
        400: "Bad Request"
    }
)
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login_view(request):
    """
    User login endpoint
    """
    try:
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, username=email, password=password)
            if user:
                if not user.is_active:
                    return Response(
                        {'error': 'User account is disabled.'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                # Generate tokens with custom claims
                refresh = RefreshToken.for_user(user)
                user_id = str(user.id)
                refresh['user_id'] = user_id
                refresh['email'] = user.email
                refresh['role'] = user.role
                access_token = refresh.access_token
                access_token['user_id'] = user_id
                access_token['email'] = user.email
                access_token['role'] = user.role
                tokens = {
                    'refresh': str(refresh),
                    'access': str(access_token),
                }
                return Response({
                    'tokens': tokens,
                    'user': {
                        'id': user_id,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'role': user.role
                    }
                })
            else:
                return Response(
                    {'error': 'Invalid credentials.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except DatabaseError as e:
        return Response(
            {'error': 'Database connection error. Please try again.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@swagger_auto_schema(
    method='post',
    request_body=RegisterSerializer,
    responses={
        201: openapi.Response(
            description="User registered successfully",
            examples={
                "application/json": {
                    "user": {
                        "id": 1,
                        "username": "john_doe",
                        "email": "john@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "role": "viewer"
                    },
                    "message": "User registered successfully"
                }
            }
        ),
        400: "Bad Request"
    }
)
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_view(request):
    """
    User registration endpoint
    """
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'user': UserSerializer(user).data,
            'message': 'User registered successfully'
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    responses={
        200: UserSerializer,
        401: "Unauthorized"
    }
)
@api_view(['GET'])
def profile_view(request):
    """
    Get current user profile
    """
    try:
        if not request.user or not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@swagger_auto_schema(
    method='post',
    request_body=ChangePasswordSerializer,
    responses={
        200: openapi.Response(
            description="Password changed successfully",
            examples={
                "application/json": {
                    "message": "Password changed successfully"
                }
            }
        ),
        400: "Bad Request"
    }
)
@api_view(['POST'])
def change_password_view(request):
    """
    Change user password
    """
    serializer = ChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        if user.check_password(serializer.validated_data['old_password']):
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            update_session_auth_hash(request, user)
            return Response({'message': 'Password changed successfully'})
        else:
            return Response(
                {'error': 'Old password is incorrect'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    responses={
        200: openapi.Response(
            description="Logged out successfully",
            examples={
                "application/json": {
                    "message": "Logged out successfully"
                }
            }
        )
    }
)
@api_view(['POST'])
def logout_view(request):
    """
    User logout endpoint
    """
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({'message': 'Logged out successfully'})
    except Exception as e:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def update_role_view(request):
    """
    Update user role (admin only)
    """
    if request.user.role != 'admin':
        return Response(
            {'error': 'Only administrators can update roles.'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    user_id = request.data.get('user_id')
    new_role = request.data.get('role')
    
    if not user_id or not new_role:
        return Response(
            {'error': 'Both user_id and role are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if new_role not in ['admin', 'analyst', 'viewer']:
        return Response(
            {'error': 'Invalid role. Must be one of: admin, analyst, viewer'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = CustomUser.objects.get(id=user_id)
        user.role = new_role
        user.save()
        return Response({
            'message': f'User role updated to {new_role}',
            'user': UserSerializer(user).data
        })
    except CustomUser.DoesNotExist:
        return Response(
            {'error': 'User not found.'},
            status=status.HTTP_404_NOT_FOUND
        )

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data['email']
                password = serializer.validated_data['password']
                user = authenticate(request, username=email, password=password)
                
                if user:
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'user': UserSerializer(user).data
                    })
                else:
                    return Response({
                        'error': 'Invalid credentials'
                    }, status=status.HTTP_401_UNAUTHORIZED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserProfileView(APIView):
    def get(self, request):
        try:
            serializer = UserSerializer(request.user)
            return Response(serializer.data)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        try:
            serializer = UserSerializer(request.user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)