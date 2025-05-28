from django.core.management.base import BaseCommand
from apps.authentication.models import CustomUser

class Command(BaseCommand):
    help = 'Updates superuser role to admin'

    def handle(self, *args, **options):
        superusers = CustomUser.objects.filter(is_superuser=True)
        updated_count = 0
        
        for user in superusers:
            if user.role != 'admin':
                user.role = 'admin'
                user.save()
                updated_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully updated role for user {user.email}')
                )
        
        if updated_count == 0:
            self.stdout.write(
                self.style.WARNING('No superusers needed role update')
            ) 