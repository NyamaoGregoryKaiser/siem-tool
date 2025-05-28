from rest_framework_simplejwt.tokens import RefreshToken
from bson import ObjectId

def update_jwt_claims(token, user):
    """
    Update JWT token claims with user information
    """
    # Convert ObjectId to string for JWT token
    user_id = str(user.id) if isinstance(user.id, ObjectId) else str(user.id) if user.id else None
    token['user_id'] = user_id
    token['email'] = user.email
    token['role'] = user.role
    return token 