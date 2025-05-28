import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import Log
from .serializers import LogSerializer

logger = logging.getLogger(__name__)

class LogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            # Accept the connection first
            await self.accept()
            logger.info("WebSocket connection accepted")
            
            # Then join the logs group
            await self.channel_layer.group_add(
                "logs",
                self.channel_name
            )
            logger.info("Joined logs group")
            
            # Send initial logs
            try:
                logs = await self.get_recent_logs()
                await self.send(text_data=json.dumps({
                    'type': 'initial_logs',
                    'logs': logs
                }))
                logger.info("Initial logs sent successfully")
            except Exception as e:
                logger.error(f"Error fetching initial logs: {str(e)}")
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'Failed to fetch initial logs'
                }))
                
        except Exception as e:
            logger.error(f"Error in connect: {str(e)}")
            # Try to send an error message before closing
            try:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'Connection failed'
                }))
            except:
                pass

    async def disconnect(self, close_code):
        try:
            logger.info(f"Disconnecting with code: {close_code}")
            await self.channel_layer.group_discard(
                "logs",
                self.channel_name
            )
        except Exception as e:
            logger.error(f"Error in disconnect: {str(e)}")

    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type', '')
            
            if message_type == 'filter_logs':
                try:
                    filters = text_data_json.get('filters', {})
                    logs = await self.get_filtered_logs(filters)
                    await self.send(text_data=json.dumps({
                        'type': 'filtered_logs',
                        'logs': logs
                    }))
                except Exception as e:
                    logger.error(f"Error filtering logs: {str(e)}")
                    await self.send(text_data=json.dumps({
                        'type': 'error',
                        'message': 'Failed to filter logs'
                    }))
            elif message_type == 'ping':
                # Handle ping messages to keep the connection alive
                await self.send(text_data=json.dumps({
                    'type': 'pong'
                }))
        except json.JSONDecodeError:
            logger.error("Invalid JSON received")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid message format'
            }))
        except Exception as e:
            logger.error(f"Error in receive: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Internal server error'
            }))

    async def log_message(self, event):
        try:
            await self.send(text_data=json.dumps(event))
        except Exception as e:
            logger.error(f"Error in log_message: {str(e)}")

    @database_sync_to_async
    def get_recent_logs(self):
        try:
            logs = Log.objects.all().order_by('-timestamp')[:100]
            return LogSerializer(logs, many=True).data
        except Exception as e:
            logger.error(f"Error in get_recent_logs: {str(e)}")
            return []

    @database_sync_to_async
    def get_filtered_logs(self, filters):
        try:
            queryset = Log.objects.all()
            
            if filters.get('source_ip'):
                queryset = queryset.filter(source_ip__icontains=filters['source_ip'])
            if filters.get('destination_ip'):
                queryset = queryset.filter(destination_ip__icontains=filters['destination_ip'])
            if filters.get('severity'):
                queryset = queryset.filter(severity=filters['severity'])
            if filters.get('start_date'):
                queryset = queryset.filter(timestamp__gte=filters['start_date'])
            if filters.get('end_date'):
                queryset = queryset.filter(timestamp__lte=filters['end_date'])
                
            return LogSerializer(queryset.order_by('-timestamp')[:100], many=True).data
        except Exception as e:
            logger.error(f"Error in get_filtered_logs: {str(e)}")
            return [] 