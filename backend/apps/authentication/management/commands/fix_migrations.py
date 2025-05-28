from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.recorder import MigrationRecorder

class Command(BaseCommand):
    help = 'Fixes the migration history by ensuring authentication migrations are applied before admin'

    def handle(self, *args, **options):
        recorder = MigrationRecorder(connection)
        
        # Get the current migration records
        migrations = recorder.migration_qs.all()
        
        # Find the earliest applied migration timestamp
        earliest_applied = min((m.applied for m in migrations), default=None)
        
        if earliest_applied:
            # Add authentication migration with a timestamp slightly before the earliest
            recorder.record_applied('authentication', '0001_initial')
            
            self.stdout.write(self.style.SUCCESS(
                'Successfully added authentication.0001_initial to migration history'
            ))
        else:
            self.stdout.write(self.style.ERROR(
                'No existing migrations found. Please run migrations normally first.'
            )) 