from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
import uuid
from decouple import config

class CustomUserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        if not extra_fields.get('username'):
            extra_fields['username'] = email  # fallback to email as username
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')  # Set role to admin for superusers
        if not extra_fields.get('username'):
            extra_fields['username'] = email  # fallback to email as username
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    # Use a simple string ID
    id = models.CharField(primary_key=True, max_length=36, default=uuid.uuid4)
    
    # Override username to be optional since we're using email
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    role = models.CharField(
        max_length=20,
        choices=[
            ('admin', 'Administrator'),
            ('analyst', 'Security Analyst'),
            ('viewer', 'Viewer'),
        ],
        default='viewer'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.CharField(max_length=45, null=True, blank=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']  # Removed username from required fields
    
    # Fix the reverse accessor conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )
    
    objects = CustomUserManager()
    
    class Meta:
        db_table = 'users'
        swappable = 'AUTH_USER_MODEL'
        
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
        
    def get_id(self):
        """
        Get the user's ID as a string
        """
        return str(self.id)