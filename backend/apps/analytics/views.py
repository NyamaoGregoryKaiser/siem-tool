from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from datetime import datetime, timedelta
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from pymongo import MongoClient
from django.conf import settings

def get_mongo_client():
    db_config = settings.DATABASES['default']['CLIENT']
    client = MongoClient(db_config['host'])
    db = client[settings.DATABASES['default']['NAME']]
    return db

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('days', openapi.IN_QUERY, description="Number of days for trend analysis", type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: openapi.Response(
            description="Security trends data",
            examples={
                "application/json": {
                    "daily_trends": [
                        {"date": "2024-01-01", "total": 1234, "critical": 12, "high": 45},
                    ],
                    "threat_sources": [
                        {"country": "Unknown", "count": 500},
                        {"country": "China", "count": 200}
                    ]
                }
            }
        )
    }
)
@api_view(['GET'])
def get_security_trends(request):
    """
    Get security trends and analytics data
    """
    try:
        db = get_mongo_client()
        db_table = db['logs']
        
        days = int(request.GET.get('days', 7))
        start_date = timezone.now() - timedelta(days=days)
        
        # Daily trends
        pipeline = [
            {'$match': {'timestamp': {'$gte': start_date}}},
            {'$group': {
                '_id': {
                    'year': {'$year': '$timestamp'},
                    'month': {'$month': '$timestamp'},
                    'day': {'$dayOfMonth': '$timestamp'}
                },
                'total': {'$sum': 1},
                'critical': {
                    '$sum': {'$cond': [{'$eq': ['$severity', 'critical']}, 1, 0]}
                },
                'high': {
                    '$sum': {'$cond': [{'$eq': ['$severity', 'high']}, 1, 0]}
                },
                'medium': {
                    '$sum': {'$cond': [{'$eq': ['$severity', 'medium']}, 1, 0]}
                },
                'low': {
                    '$sum': {'$cond': [{'$eq': ['$severity', 'low']}, 1, 0]}
                }
            }},
            {'$sort': {'_id.year': 1, '_id.month': 1, '_id.day': 1}}
        ]
        
        daily_data = list(db_table.aggregate(pipeline))
        daily_trends = []
        for item in daily_data:
            date_str = f"{item['_id']['year']}-{item['_id']['month']:02d}-{item['_id']['day']:02d}"
            daily_trends.append({
                'date': date_str,
                'total': item['total'],
                'critical': item['critical'],
                'high': item['high'],
                'medium': item['medium'],
                'low': item['low']
            })
        
        # Threat sources by country
        pipeline = [
            {'$match': {'timestamp': {'$gte': start_date}}},
            {'$group': {'_id': '$country', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        
        threat_sources = list(db_table.aggregate(pipeline))
        threat_sources = [{'country': item['_id'] or 'Unknown', 'count': item['count']} for item in threat_sources]
        
        # Attack types distribution
        pipeline = [
            {'$match': {'timestamp': {'$gte': start_date}}},
            {'$group': {'_id': '$log_type', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        
        attack_types = list(db_table.aggregate(pipeline))
        attack_types = [{'type': item['_id'], 'count': item['count']} for item in attack_types]
        
        # Top targeted ports
        pipeline = [
            {'$match': {
                'timestamp': {'$gte': start_date},
                'destination_port': {'$ne': None}
            }},
            {'$group': {'_id': '$destination_port', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        
        top_ports = list(db_table.aggregate(pipeline))
        top_ports = [{'port': item['_id'], 'count': item['count']} for item in top_ports]
        
        return Response({
            'daily_trends': daily_trends,
            'threat_sources': threat_sources,
            'attack_types': attack_types,
            'top_targeted_ports': top_ports
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="Geographic attack data",
            examples={
                "application/json": {
                    "attacks_by_country": [
                        {"country": "China", "lat": 35.0, "lng": 105.0, "count": 500},
                    ]
                }
            }
        )
    }
)
@api_view(['GET'])
def get_geographic_data(request):
    """
    Get geographic distribution of attacks
    """
    try:
        db = get_mongo_client()
        db_table = db['logs']
        
        # Get attacks by country with coordinates (simplified mapping)
        country_coords = {
            'China': {'lat': 35.0, 'lng': 105.0},
            'United States': {'lat': 39.8, 'lng': -98.5},
            'Russia': {'lat': 61.5, 'lng': 105.3},
            'India': {'lat': 20.6, 'lng': 78.9},
            'Germany': {'lat': 51.2, 'lng': 10.4},
            'United Kingdom': {'lat': 55.4, 'lng': -3.4},
            'France': {'lat': 46.6, 'lng': 2.2},
            'Brazil': {'lat': -14.2, 'lng': -51.9},
            'Canada': {'lat': 56.1, 'lng': -106.3},
            'Australia': {'lat': -25.3, 'lng': 133.8},
        }
        
        pipeline = [
            {'$match': {'country': {'$ne': None}}},
            {'$group': {'_id': '$country', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 20}
        ]
        
        country_data = list(db_table.aggregate(pipeline))
        
        attacks_by_country = []
        for item in country_data:
            country = item['_id']
            coords = country_coords.get(country, {'lat': 0, 'lng': 0})
            attacks_by_country.append({
                'country': country,
                'lat': coords['lat'],
                'lng': coords['lng'],
                'count': item['count']
            })
        
        return Response({
            'attacks_by_country': attacks_by_country
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="Real-time activity data",
            examples={
                "application/json": {
                    "current_activity": {
                        "logs_per_minute": 45,
                        "active_alerts": 12,
                        "recent_attacks": [
                            {"timestamp": "2024-01-01T12:00:00Z", "source": "192.168.1.1", "type": "brute_force"}
                        ]
                    }
                }
            }
        )
    }
)
@api_view(['GET'])
def get_realtime_activity(request):
    """
    Get real-time security activity
    """
    try:
        db = get_mongo_client()
        db_table = db['logs']
        alerts_db_table = db['alerts']
        
        # Logs in the last minute
        one_minute_ago = timezone.now() - timedelta(minutes=1)
        logs_per_minute = db_table.count_documents({
            'timestamp': {'$gte': one_minute_ago}
        })
        
        # Active alerts
        active_alerts = alerts_db_table.count_documents({
            'status': {'$in': ['open', 'investigating']}
        })
        
        # Recent high-severity attacks (last 10 minutes)
        ten_minutes_ago = timezone.now() - timedelta(minutes=10)
        pipeline = [
            {'$match': {
                'timestamp': {'$gte': ten_minutes_ago},
                'severity': {'$in': ['high', 'critical']}
            }},
            {'$sort': {'timestamp': -1}},
            {'$limit': 10}
        ]
        
        recent_attacks = list(db_table.aggregate(pipeline))
        recent_attacks_formatted = []
        for attack in recent_attacks:
            recent_attacks_formatted.append({
                'timestamp': attack['timestamp'].isoformat(),
                'source': attack['source_ip'],
                'type': attack['log_type'],
                'severity': attack['severity'],
                'event': attack['event_name']
            })
        
        return Response({
            'current_activity': {
                'logs_per_minute': logs_per_minute,
                'active_alerts': active_alerts,
                'recent_attacks': recent_attacks_formatted
            }
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=500)