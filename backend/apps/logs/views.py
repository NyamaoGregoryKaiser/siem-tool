from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Q, Count
from django.utils import timezone
from datetime import datetime, timedelta
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from pymongo import MongoClient
from django.conf import settings
import json
from django.db import connection
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from bson import ObjectId
from dateutil.parser import parse as parse_date
import time
import random

from .models import SecurityLog, AlertRule, Alert
from .serializers import (
    SecurityLogSerializer, SecurityLogListSerializer, SecurityLogStatsSerializer,
    AlertRuleSerializer, AlertSerializer, AlertUpdateSerializer, LogFilterSerializer
)

# In-memory cache for dashboard stats
_dashboard_stats_cache = None
_dashboard_stats_cache_time = 0

# MongoDB connection for complex queries
def get_mongo_client():
    db_config = settings.DATABASES['default']['CLIENT']
    client = MongoClient(db_config['host'])
    db = client[settings.DATABASES['default']['NAME']]
    return db

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Page size", type=openapi.TYPE_INTEGER),
        openapi.Parameter('start_date', openapi.IN_QUERY, description="Start date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('end_date', openapi.IN_QUERY, description="End date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('source_ip', openapi.IN_QUERY, description="Source IP address", type=openapi.TYPE_STRING),
        openapi.Parameter('log_type', openapi.IN_QUERY, description="Log type", type=openapi.TYPE_STRING),
        openapi.Parameter('Level__gte', openapi.IN_QUERY, description="Level greater than or equal to", type=openapi.TYPE_INTEGER),
        openapi.Parameter('Level__lte', openapi.IN_QUERY, description="Level less than or equal to", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search term", type=openapi.TYPE_STRING),
    ],
    responses={200: SecurityLogListSerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_logs(request):
    """
    Get security logs with filtering and pagination using PyMongo directly.
    """
    try:
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 10))
        skip = (page - 1) * page_size

        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs']

        # Build filter
        query = {}
        if request.GET.get('search'):
            query['$or'] = [
                {'Message': {'$regex': request.GET['search'], '$options': 'i'}},
                {'ComputerName': {'$regex': request.GET['search'], '$options': 'i'}},
                {'SourceIP': {'$regex': request.GET['search'], '$options': 'i'}},
            ]
        if request.GET.get('source_ip'):
            query['SourceIP'] = request.GET['source_ip']
        if request.GET.get('Level__gte'):
            query['Level'] = query.get('Level', {})
            query['Level']['$gte'] = int(request.GET['Level__gte'])
        if request.GET.get('Level__lte'):
            query['Level'] = query.get('Level', {})
            query['Level']['$lte'] = int(request.GET['Level__lte'])

        # Date filtering
        time_filter = {}
        if request.GET.get('start_date'):
            time_filter['$gte'] = parse_date(request.GET['start_date'])
        if request.GET.get('end_date'):
            time_filter['$lte'] = parse_date(request.GET['end_date'])
        if time_filter:
            query['TimeGenerated'] = time_filter

        total = logs_collection.count_documents(query)
        logs = list(
            logs_collection.find(query)
            .sort('TimeGenerated', -1)
            .skip(skip)
            .limit(page_size)
        )

        # Convert ObjectId to string
        for log in logs:
            log['_id'] = str(log['_id'])

        return Response({
            'logs': logs,
            'total': total,
            'page': page,
            'page_size': page_size
        })
    except Exception as e:
        import traceback
        print('ERROR in get_logs:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: SecurityLogSerializer}
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_log_detail(request, log_id):
    """
    Get detailed information about a specific log using PyMongo directly.
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs']

        log = logs_collection.find_one({'_id': ObjectId(log_id)})
        if not log:
            return Response({'error': 'Log not found'}, status=404)
        log['_id'] = str(log['_id'])
        return Response(log)
    except Exception as e:
        import traceback
        print('ERROR in get_log_detail:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: SecurityLogStatsSerializer}
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_log_stats(request):
    """
    Get log statistics for dashboard cards (cached for 10 seconds)
    """
    global _dashboard_stats_cache, _dashboard_stats_cache_time
    try:
        now = time.time()
        # Serve from cache if not expired
        if _dashboard_stats_cache and now - _dashboard_stats_cache_time < 10:
            return Response(_dashboard_stats_cache)

        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs'] if 'logs' in db.list_collection_names() else None

        # Total Security Events
        total_events = logs_collection.count_documents({}) if logs_collection is not None else 0

        # Critical Alerts (logs with EventType 'FailureAudit' or Level >= 13)
        critical_alerts = 0
        if logs_collection is not None:
            critical_alerts = logs_collection.count_documents({
                '$or': [
                    {'EventType': 'FailureAudit'},
                    {'Level': {'$gte': 13}}
                ]
            })

        # Active Threats (critical records from the last hour)
        active_threats = 0
        if logs_collection is not None:
            one_hour_ago = datetime.now() - timedelta(hours=1)
            active_threats = logs_collection.count_documents({
                '$and': [
                    {
                        '$or': [
                            {'EventType': 'FailureAudit'},
                            {'Level': {'$gte': 13}}
                        ]
                    },
                    {
                        '$or': [
                            {'TimeGenerated': {'$gte': one_hour_ago}},
                            {'parsedTime': {'$gte': one_hour_ago}}
                        ]
                    }
                ]
            })

        # System Health: Weighted calculation based on event types
        system_health = 0
        if logs_collection is not None and total_events > 0:
            # Count events by type
            event_counts = logs_collection.aggregate([
                {
                    '$group': {
                        '_id': '$EventType',
                        'count': {'$sum': 1}
                    }
                }
            ])
            
            # Convert to dictionary for easier access
            event_type_counts = {doc['_id']: doc['count'] for doc in event_counts}
            
            # Calculate weighted health score
            # SuccessAudit and Information are positive indicators
            # Error and Warning are negative indicators
            # FailureAudit is a strong negative indicator
            positive_events = (
                event_type_counts.get('SuccessAudit', 0) +
                event_type_counts.get('Information', 0) +
                event_type_counts.get('Success', 0)
            )
            
            negative_events = (
                event_type_counts.get('Error', 0) * 1.5 +  # Weight errors more heavily
                event_type_counts.get('Warning', 0) * 2 +  # Weight warnings even more
                event_type_counts.get('FailureAudit', 0) * 3  # Weight failures most heavily
            )
            
            # Calculate health percentage
            if (positive_events + negative_events) > 0:
                system_health = round(
                    (positive_events / (positive_events + negative_events)) * 100
                )
            else:
                system_health = 100  # If no events, system is considered healthy

        stats = {
            'total_events': total_events,
            'critical_alerts': critical_alerts,
            'active_threats': active_threats,
            'system_health': system_health
        }
        # Update cache
        _dashboard_stats_cache = stats
        _dashboard_stats_cache_time = now
        return Response(stats)
    except Exception as e:
        import traceback
        print('ERROR in get_log_stats:', e)
        traceback.print_exc()
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@swagger_auto_schema(
    method='get',
    responses={200: AlertSerializer(many=True)}
)
@api_view(['GET'])
def get_alerts(request):
    """
    Get security alerts
    """
    queryset = Alert.objects.all()
    
    # Filter by status
    if request.GET.get('status'):
        queryset = queryset.filter(status=request.GET.get('status'))
    
    # Filter by severity
    if request.GET.get('severity'):
        queryset = queryset.filter(severity=request.GET.get('severity'))
    
    # Pagination
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 20))
    start = (page - 1) * page_size
    end = start + page_size
    
    total_count = queryset.count()
    alerts = queryset[start:end]
    
    serializer = AlertSerializer(alerts, many=True)
    
    return Response({
        'results': serializer.data,
        'count': total_count,
        'page': page,
        'page_size': page_size,
        'total_pages': (total_count + page_size - 1) // page_size
    })

@swagger_auto_schema(
    method='put',
    request_body=AlertUpdateSerializer,
    responses={200: AlertSerializer}
)
@api_view(['PUT'])
def update_alert(request, alert_id):
    """
    Update alert status and details
    """
    try:
        alert = Alert.objects.get(_id=alert_id)
        serializer = AlertUpdateSerializer(alert, data=request.data, partial=True)
        
        if serializer.is_valid():
            if request.data.get('status') == 'resolved':
                serializer.validated_data['resolved_at'] = timezone.now()
            
            serializer.save()
            
            # Return full alert data
            full_serializer = AlertSerializer(alert)
            return Response(full_serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except Alert.DoesNotExist:
        return Response({'error': 'Alert not found'}, status=status.HTTP_404_NOT_FOUND)

@swagger_auto_schema(
    method='get',
    responses={200: AlertRuleSerializer(many=True)}
)
@api_view(['GET'])
def get_alert_rules(request):
    """
    Get alert rules
    """
    rules = AlertRule.objects.all()
    serializer = AlertRuleSerializer(rules, many=True)
    return Response(serializer.data)

@swagger_auto_schema(
    method='post',
    request_body=AlertRuleSerializer,
    responses={201: AlertRuleSerializer}
)
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def create_alert_rule(request):
    """
    Create new alert rule
    """
    serializer = AlertRuleSerializer(data=request.data)
    if serializer.is_valid():
        serializer.validated_data['created_by'] = request.user.username
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def test_db_connection(request):
    """Test endpoint to verify database connection and log count."""
    try:
        # Get log count
        log_count = SecurityLog.objects.count()
        
        # Get user count from raw MongoDB query
        with connection.cursor() as cursor:
            cursor.execute("db.users.count()")
            user_count = cursor.fetchone()[0]
        
        return Response({
            'status': 'success',
            'message': 'Database connection successful',
            'data': {
                'log_count': log_count,
                'user_count': user_count,
                'database_name': 'log_anomaly'
            }
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)

def broadcast_new_log(log):
    """
    Broadcast a new log to all connected WebSocket clients
    """
    channel_layer = get_channel_layer()
    serializer = SecurityLogListSerializer(log)
    async_to_sync(channel_layer.group_send)(
        "logs",
        {
            "type": "log_message",
            "data": serializer.data
        }
    )

@api_view(['POST'])
def create_log(request):
    """
    Create a new security log and broadcast it to all connected clients
    """
    serializer = SecurityLogSerializer(data=request.data)
    if serializer.is_valid():
        log = serializer.save()
        broadcast_new_log(log)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alerts_by_agent(request):
    """
    Return a list of agents (devices) and their log counts, grouped by ComputerName in logs.
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs'] if 'logs' in db.list_collection_names() else None
        if logs_collection is None:
            return Response([])
        pipeline = [
            {"$group": {"_id": "$ComputerName", "count": {"$sum": 1}}},
            {"$project": {"agent": {"$ifNull": ["$_id", "Unknown"]}, "count": 1, "_id": 0}},
            {"$sort": {"count": -1}}
        ]
        results = list(logs_collection.aggregate(pipeline))
        return Response(results)
    except Exception as e:
        import traceback
        print('ERROR in alerts_by_agent:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(description="List of computer names")}
)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_computer_names(request):
    """
    Get list of unique computer names from logs
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs']

        # Get unique computer names
        computer_names = logs_collection.distinct('ComputerName')
        
        # Filter out None/empty values and sort
        computer_names = sorted([name for name in computer_names if name])
        
        return Response(computer_names)
    except Exception as e:
        import traceback
        print('ERROR in get_computer_names:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(description="Critical logs count by device")}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_critical_logs_by_device(request):
    """
    Get count of critical logs by device for the last 24 hours
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs']

        # Calculate timestamp for 24 hours ago
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        twenty_four_hours_ago_str = twenty_four_hours_ago.strftime('%Y-%m-%d %H:%M:%S +0300')

        # Pipeline to get critical logs count by device
        pipeline = [
            # First convert string dates to proper date objects
            {
                "$addFields": {
                    "parsedTime": {
                        "$dateFromString": {
                            "dateString": "$TimeGenerated",
                            "onError": "$TimeGenerated"  # Keep original if parsing fails
                        }
                    }
                }
            },
            # Match logs from the last 24 hours
            {
                "$match": {
                    "$or": [
                        {"parsedTime": {"$gte": twenty_four_hours_ago}},
                        {"TimeGenerated": {"$gte": twenty_four_hours_ago_str}}
                    ]
                }
            },
            # Group by ComputerName and count critical/high events
            {
                "$group": {
                    "_id": "$ComputerName",
                    "critical": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$EventType", "FailureAudit"]},
                                1,
                                0
                            ]
                        }
                    },
                    "high": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$EventType", "Warning"]},
                                1,
                                0
                            ]
                        }
                    }
                }
            },
            # Format the output
            {
                "$project": {
                    "device": "$_id",
                    "critical": 1,
                    "high": 1,
                    "_id": 0
                }
            }
        ]

        results = list(logs_collection.aggregate(pipeline))
        
        # Convert to dictionary format for easier frontend consumption
        formatted_results = {}
        for result in results:
            formatted_results[result['device']] = {
                'critical': result['critical'],
                'high': result['high']
            }
        
        return Response(formatted_results)
    except Exception as e:
        import traceback
        print('ERROR in get_critical_logs_by_device:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(description="Daily counts of logs grouped by severity for the Area Chart for the last 7 days")}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alerts_evolution(request):
    """
    Return daily counts of logs grouped by severity for the Area Chart for the last 7 days.
    Maps EventTypes to severity levels:
    - FailureAudit -> critical
    - Warning -> high
    - Error -> moderate
    - SuccessAudit, Information, Success -> low
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs'] if 'logs' in db.list_collection_names() else None
        if logs_collection is None:
            return Response([])

        # Calculate timestamp for 7 days ago
        seven_days_ago = datetime.now() - timedelta(days=7)

        # Aggregate logs by day and severity
        pipeline = [
            # First convert string dates to proper date objects
            {"$addFields": {
                "parsedTime": {
                    "$dateFromString": {
                        "dateString": "$TimeGenerated",
                        "onError": "$TimeGenerated"  # Keep original if parsing fails
                    }
                }
            }},
            # Match only logs from the last 7 days
            {"$match": {
                "$or": [
                    {"parsedTime": {"$gte": seven_days_ago}},
                    {"TimeGenerated": {"$gte": seven_days_ago.isoformat()}}
                ]
            }},
            # Map EventType to severity
            {"$addFields": {
                "severity": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$EventType", "FailureAudit"]}, "then": "critical"},
                            {"case": {"$eq": ["$EventType", "Warning"]}, "then": "high"},
                            {"case": {"$eq": ["$EventType", "Error"]}, "then": "moderate"}
                        ],
                        "default": "low"  # SuccessAudit, Information, Success -> low
                    }
                },
                "date": {
                    "$cond": {
                        "if": {"$eq": [{"$type": "$parsedTime"}, "date"]},
                        "then": {"$dateToString": {"format": "%Y-%m-%d", "date": "$parsedTime"}},
                        "else": {"$substr": ["$TimeGenerated", 0, 10]}  # Extract YYYY-MM-DD from string
                    }
                }
            }},
            {"$group": {
                "_id": {
                    "date": "$date",
                    "severity": "$severity"
                },
                "count": {"$sum": 1}
            }},
            {"$group": {
                "_id": "$_id.date",
                "counts": {"$push": {"severity": "$_id.severity", "count": "$count"}}
            }},
            {"$sort": {"_id": 1}}
        ]
        results = list(logs_collection.aggregate(pipeline))
        
        # Format results as [{date, critical, high, moderate, low}]
        formatted = []
        for entry in results:
            row = {"date": entry["_id"], "critical": 0, "high": 0, "moderate": 0, "low": 0}
            for c in entry["counts"]:
                    row[c["severity"]] = c["count"]
            formatted.append(row)
        return Response(formatted)
    except Exception as e:
        import traceback
        print('ERROR in alerts_evolution:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(description="MITRE ATT&CK distribution data")}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mitre_attack(request):
    """
    Return MITRE ATT&CK distribution data based on Technique field.
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs'] if 'logs' in db.list_collection_names() else None
        if logs_collection is None:
            return Response([])

        # Pipeline to get MITRE ATT&CK distribution
        pipeline = [
            # Match only logs with valid Technique values
            {
                "$match": {
                    "Technique": {
                        "$ne": None,
                        "$ne": "",
                        "$ne": "null",
                        "$exists": True,
                        "$regex": "^T\\d+(\\.\\d+)?$"  # Match MITRE technique format (e.g., T1098 or T1110.001)
                    }
                }
            },
            # Group by Technique and count
            {
                "$group": {
                    "_id": "$Technique",
                    "value": {"$sum": 1}
                }
            },
            # Format the output
            {
                "$project": {
                    "name": "$_id",
                    "value": 1,
                    "_id": 0
                }
            },
            # Sort by value descending
            {
                "$sort": {"value": -1}
            }
        ]

        try:
            results = list(logs_collection.aggregate(pipeline))
            return Response(results)
        except Exception as e:
            print(f"Error in MongoDB aggregation: {str(e)}")
            return Response({'error': 'Error processing MITRE ATT&CK data'}, status=500)

    except Exception as e:
        import traceback
        print('ERROR in mitre_attack:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(description="OS severity distribution data")}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def os_severity_distribution(request):
    """
    Return severity distribution by operating system.
    Records without an OperatingSystem field are considered as Windows 11 Home.
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs'] if 'logs' in db.list_collection_names() else None
        if logs_collection is None:
            return Response([])

        # Pipeline to get OS severity distribution
        pipeline = [
            # Add a field for OS, defaulting to Windows 11 Home if not present
            {
                "$addFields": {
                    "OperatingSystem": {
                        "$ifNull": ["$OperatingSystem", "Windows 11 Home"]
                    }
                }
            },
            # Group by OS and EventType
            {
                "$group": {
                    "_id": {
                        "os": "$OperatingSystem",
                        "level": "$EventType"
                    },
                    "count": {"$sum": 1}
                }
            },
            # Sort by OS and count
            {
                "$sort": {
                    "_id.os": 1,
                    "count": -1
                }
            }
        ]

        try:
            results = list(logs_collection.aggregate(pipeline))
            
            # Format results for frontend
            formatted_results = {}
            for result in results:
                os_name = result['_id']['os']
                if os_name not in formatted_results:
                    formatted_results[os_name] = {
                        'critical': 0,
                        'high': 0,
                        'moderate': 0,
                        'low': 0
                    }
                
                # Map EventType to severity
                event_type = result['_id']['level']
                if event_type == 'FailureAudit':
                    formatted_results[os_name]['critical'] += result['count']
                elif event_type == 'Warning':
                    formatted_results[os_name]['high'] += result['count']
                elif event_type == 'Error':
                    formatted_results[os_name]['moderate'] += result['count']
                elif event_type in ['SuccessAudit', 'Information', 'Success']:
                    formatted_results[os_name]['low'] += result['count']

            # Convert to array format
            final_results = [
                {
                    'os': os_name,
                    'critical': data['critical'],
                    'high': data['high'],
                    'moderate': data['moderate'],
                    'low': data['low']
                }
                for os_name, data in formatted_results.items()
            ]

            return Response(final_results)
        except Exception as e:
            print(f"Error in MongoDB aggregation: {str(e)}")
            return Response({'error': 'Error processing OS severity data'}, status=500)

    except Exception as e:
        import traceback
        print('ERROR in os_severity_distribution:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(description="Critical alerts from the past 10 hours")}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def critical_alerts(request):
    """
    Return critical alerts from the past 10 hours.
    """
    try:
        # Connect to MongoDB
        client = MongoClient(settings.DATABASES['logs']['CLIENT']['host'])
        db = client[settings.DATABASES['logs']['NAME']]
        logs_collection = db['logs'] if 'logs' in db.list_collection_names() else None
        if logs_collection is None:
            return Response([])

        # Calculate timestamp for 10 hours ago
        ten_hours_ago = datetime.now() - timedelta(hours=10)
        ten_hours_ago_str = ten_hours_ago.strftime('%Y-%m-%d %H:%M:%S +0300')
        print(f"Debug - Looking for alerts since: {ten_hours_ago_str}")

        # Generate random limit between 3 and 5
        random_limit = random.randint(3, 5)
        print(f"Debug - Using random limit: {random_limit}")

        # Pipeline to get critical alerts
        pipeline = [
            # Match both FailureAudit and Error events from the last 10 hours
            {
                "$match": {
                    "$and": [
                        {
                            "$or": [
                                {"EventType": "FailureAudit"},
                                {"EventType": "Error"}
                            ]
                        },
                        {"TimeGenerated": {"$gte": ten_hours_ago_str}}
                    ]
                }
            },
            # Project all fields we need
            {
                "$project": {
                    "TimeGenerated": 1,
                    "ComputerName": 1,
                    "OperatingSystem": 1,
                    "EventType": 1,
                    "_id": 1
                }
            },
            # Sort by timestamp descending
            {
                "$sort": {
                    "TimeGenerated": -1
                }
            },
            # Limit to random number between 3 and 5
            {
                "$limit": random_limit
            }
        ]

        try:
            # Execute the pipeline
            results = list(logs_collection.aggregate(pipeline))
            print(f"Debug - Found {len(results)} critical alerts in the last 10 hours")
            
            # Debug print each result
            for idx, result in enumerate(results):
                print(f"Debug - Result {idx + 1}:")
                print(f"  TimeGenerated: {result.get('TimeGenerated')}")
                print(f"  ComputerName: {result.get('ComputerName')}")
                print(f"  OperatingSystem: {result.get('OperatingSystem')}")
                print(f"  EventType: {result.get('EventType')}")
                print(f"  ID: {result.get('_id')}")
            
            # Format results for frontend
            formatted_results = []
            for result in results:
                formatted_result = {
                    'id': str(result.get('_id')),
                    'timestamp': result.get('TimeGenerated'),
                    'source': result.get('ComputerName', 'Unknown'),
                    'type': result.get('OperatingSystem', 'Windows 11 Home')
                }
                print(f"Debug - Formatted result: {formatted_result}")
                formatted_results.append(formatted_result)

            return Response(formatted_results)
        except Exception as e:
            print(f"Error in MongoDB aggregation: {str(e)}")
            return Response({'error': 'Error processing critical alerts'}, status=500)

    except Exception as e:
        import traceback
        print('ERROR in critical_alerts:', e)
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)