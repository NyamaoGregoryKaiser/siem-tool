from rest_framework import serializers
from .models import SecurityLog, AlertRule, Alert, Log, AnalystQueue

class SecurityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityLog
        fields = '__all__'
        read_only_fields = ('_id',)

class SecurityLogListSerializer(serializers.ModelSerializer):
    """Simplified serializer for log lists"""
    class Meta:
        model = SecurityLog
        fields = ('_id', 'TimeGenerated', 'EventID', 'Level', 'Task', 'ComputerName', 
                 'Message', 'AccountName', 'SourceIP', 'Status', 'IsAnomaly', 'severity')

class SecurityLogStatsSerializer(serializers.Serializer):
    total_logs = serializers.IntegerField()
    logs_today = serializers.IntegerField()
    critical_alerts = serializers.IntegerField()
    high_severity = serializers.IntegerField()
    top_source_ips = serializers.ListField()
    log_types_distribution = serializers.DictField()
    severity_distribution = serializers.DictField()
    hourly_distribution = serializers.ListField()

class AlertRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertRule
        fields = '__all__'
        read_only_fields = ('_id',)

class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ('_id',)

class AlertUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ('status', 'assigned_to', 'notes', 'resolved_at')

class LogFilterSerializer(serializers.Serializer):
    start_date = serializers.DateTimeField(required=False)
    end_date = serializers.DateTimeField(required=False)
    source_ip = serializers.CharField(required=False)
    destination_ip = serializers.CharField(required=False)
    log_type = serializers.ChoiceField(
        choices=[
            ('firewall', 'Firewall'),
            ('intrusion', 'Intrusion Detection'),
            ('authentication', 'Authentication'),
            ('application', 'Application'),
            ('system', 'System'),
            ('network', 'Network'),
            ('malware', 'Malware Detection'),
            ('vulnerability', 'Vulnerability'),
        ],
        required=False
    )
    severity = serializers.ChoiceField(
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        required=False
    )
    hostname = serializers.CharField(required=False)
    username = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    search = serializers.CharField(required=False)

class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = ['id', 'timestamp', 'source_ip', 'destination_ip', 
                 'event_type', 'severity', 'message', 'raw_log', 
                 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class AnalystQueueSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalystQueue
        fields = ['_id', 'log_id', 'added_by', 'added_at', 'status', 'priority', 
                 'notes', 'resolution', 'resolved_at', 'resolved_by']
        read_only_fields = ['_id', 'added_at', 'resolved_at']

class AnalystQueueUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalystQueue
        fields = ['status', 'priority', 'notes', 'resolution', 'resolved_by']