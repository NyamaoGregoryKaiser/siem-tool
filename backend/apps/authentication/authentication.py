from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        """
        Override to handle user retrieval
        """
        try:
            user_id = validated_token.get('user_id')
            if not user_id:
                return None
                
            UserModel = get_user_model()
            user = UserModel.objects.get(id=user_id)
            
            if not user.is_active:
                return None
                
            return user
        except (UserModel.DoesNotExist, ValueError, TypeError, TokenError):
            return None
        except Exception as e:
            return None 