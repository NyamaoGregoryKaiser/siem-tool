from djongo import models as djongo_models
from django.db import models
from datetime import datetime

class SecurityLog(djongo_models.Model):
    _id = djongo_models.ObjectIdField()
    TimeGenerated = models.DateTimeField(default=datetime.now)
    EventID = models.CharField(max_length=100, null=True, blank=True)
    Level = models.IntegerField(default=4)
    Task = models.CharField(max_length=100)
    Technique = models.CharField(max_length=100, null=True, blank=True)
    ComputerName = models.CharField(max_length=255)
    Message = models.TextField()
    AccountName = models.CharField(max_length=100, null=True, blank=True)
    AccountSID = models.CharField(max_length=100, null=True, blank=True)
    SessionID = models.CharField(max_length=100, null=True, blank=True)
    SourceIP = models.CharField(max_length=45)
    LogonType = models.IntegerField(null=True, blank=True)
    Status = models.CharField(max_length=50)
    IsAnomaly = models.IntegerField(default=0)
    
    # Additional fields for compatibility
    timestamp = models.DateTimeField(default=datetime.now)
    source_ip = models.CharField(max_length=45)
    destination_ip = models.CharField(max_length=45, null=True, blank=True)
    log_type = models.CharField(max_length=50, default='authentication')
    severity = models.CharField(max_length=20, default='low')
    event_name = models.CharField(max_length=200)
    hostname = models.CharField(max_length=255)
    username = models.CharField(max_length=100, null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    processed = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'logs'
        ordering = ['-TimeGenerated']
        
    def __str__(self):
        return f"{self.Message} - {self.SourceIP} - {self.TimeGenerated}"
        
    def save(self, *args, **kwargs):
        # Map MongoDB fields to Django model fields
        self.timestamp = self.TimeGenerated
        self.source_ip = self.SourceIP
        self.event_name = self.Task
        self.hostname = self.ComputerName
        self.username = self.AccountName
        
        # Map Level to severity
        if self.Level <= 2:
            self.severity = 'critical'
        elif self.Level <= 4:
            self.severity = 'high'
        elif self.Level <= 6:
            self.severity = 'medium'
        else:
            self.severity = 'low'
            
        super().save(*args, **kwargs)

class AlertRule(djongo_models.Model):
    _id = djongo_models.ObjectIdField()
    name = models.CharField(max_length=200)
    description = models.TextField()
    
    # Rule conditions
    conditions = models.JSONField(default=dict)
    severity_threshold = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        default='medium'
    )
    
    # Rule configuration
    is_active = models.BooleanField(default=True)
    frequency_limit = models.IntegerField(default=1)  # triggers per time_window
    time_window = models.IntegerField(default=300)  # seconds
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'alert_rules'
        
    def __str__(self):
        return self.name

class Alert(djongo_models.Model):
    _id = djongo_models.ObjectIdField()
    rule_name = models.CharField(max_length=200)
    title = models.CharField(max_length=300)
    description = models.TextField()
    severity = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ]
    )
    
    # Alert status
    status = models.CharField(
        max_length=20,
        choices=[
            ('open', 'Open'),
            ('investigating', 'Investigating'),
            ('resolved', 'Resolved'),
            ('false_positive', 'False Positive'),
        ],
        default='open'
    )
    
    # Related logs
    related_logs = models.JSONField(default=list)
    log_count = models.IntegerField(default=1)
    
    # Metadata
    source_ips = models.JSONField(default=list)
    affected_hosts = models.JSONField(default=list)
    tags = models.JSONField(default=list)
    
    # Timestamps
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Assignment
    assigned_to = models.CharField(max_length=100, null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'alerts'
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.title} - {self.severity} - {self.status}"

class Log(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=45)
    destination_ip = models.CharField(max_length=45)
    event_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    message = models.TextField()
    raw_log = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['destination_ip']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"{self.event_type} - {self.source_ip} -> {self.destination_ip}"

class AnalystQueue(djongo_models.Model):
    _id = djongo_models.ObjectIdField()
    log_id = models.CharField(max_length=100)  # Reference to the original log
    added_by = models.CharField(max_length=100)  # Username of the analyst
    added_at = models.DateTimeField(default=datetime.now)
    status = models.CharField(max_length=20, default='pending')  # pending, investigating, resolved
    priority = models.CharField(max_length=20, default='low')  # low, medium, high
    notes = models.TextField(null=True, blank=True)
    resolution = models.TextField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        db_table = 'analyst_queue'
        ordering = ['-added_at']

    def __str__(self):
        return f"Queue Item {self._id} - Status: {self.status}"