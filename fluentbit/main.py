from fastapi import FastAPI, Request, HTTPException
from pymongo import MongoClient
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import uvicorn
import json
from datetime import datetime
import asyncio
from collections import deque
import traceback
from bson import ObjectId

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Fluent Bit Log Receiver", version="1.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React app's origin
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# MongoDB setup
try:
    logger.info("Attempting to connect to MongoDB...")
    client = MongoClient("mongodb://localhost:27017/")
    db = client["siem_db"]
    logs_collection = db["logs"]
    # Test the connection
    client.admin.command('ping')
    logger.info("Connected to MongoDB successfully.")
except Exception as e:
    logs_collection = None
    logger.error(f"MongoDB connection failed: {e}")
    logger.error("Please ensure MongoDB is running on localhost:27017")

# Store recent logs in memory (last 1000 logs)
recent_logs = deque(maxlen=1000)

# Queue for new logs
log_queue = asyncio.Queue()

async def log_generator():
    """Generator function to yield new logs as they arrive"""
    try:
        while True:
            # Get the latest log from the queue
            log = await log_queue.get()
            if log:
                # Convert ObjectId to string for JSON serialization
                if '_id' in log and isinstance(log['_id'], ObjectId):
                    log['_id'] = str(log['_id'])
                logger.info(f"Sending log to SSE client: {log}")
                yield f"data: {json.dumps(log)}\n\n"
    except Exception as e:
        logger.error(f"Error in log generator: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        yield f"data: {json.dumps({'error': str(e)})}\n\n"

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "Log receiver is running", "mongodb_connected": logs_collection is not None}

@app.get("/live-logs")
async def live_logs():
    """Stream live logs using Server-Sent Events"""
    try:
        logger.info("New SSE connection established")
        return StreamingResponse(
            log_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )
    except Exception as e:
        logger.error(f"Error in live_logs endpoint: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logs")
async def receive_logs(request: Request):
    """
    Endpoint to receive logs from Fluent Bit
    """
    try:
        # Get raw body first for debugging
        body = await request.body()
        logger.info(f"Received raw body: {body.decode('utf-8')}")
        
        # Parse JSON
        data = await request.json()
        logger.info(f"Received log data: {data}")
        
        # Handle different log formats
        if isinstance(data, list):
            if len(data) == 2:  # [timestamp, record] format
                timestamp, record = data
                if isinstance(record, dict):
                    logs_to_process = [record]
                else:
                    try:
                        if isinstance(record, str):
                            parsed_record = json.loads(record)
                            logs_to_process = parsed_record if isinstance(parsed_record, list) else [parsed_record]
                        else:
                            logs_to_process = [{"raw_message": str(record)}]
                    except json.JSONDecodeError:
                        logs_to_process = [{"raw_message": str(record)}]
            else:
                # Handle list of logs
                logs_to_process = []
                for item in data:
                    if isinstance(item, dict):
                        logs_to_process.append(item)
                    else:
                        try:
                            if isinstance(item, str):
                                parsed_item = json.loads(item)
                                if isinstance(parsed_item, list):
                                    logs_to_process.extend(parsed_item)
                                else:
                                    logs_to_process.append(parsed_item)
                            else:
                                logs_to_process.append({"raw_message": str(item)})
                        except json.JSONDecodeError:
                            logs_to_process.append({"raw_message": str(item)})
        else:
            # Single log object
            logs_to_process = [data] if isinstance(data, dict) else [{"raw_message": str(data)}]

        # Process each log
        for log_data in logs_to_process:
            # Format the log data for display
            formatted_log = {
                'TimeGenerated': log_data.get('TimeGenerated', 'N/A'),
                'EventID': log_data.get('EventID', 'N/A'),
                'EventType': log_data.get('EventType', 'N/A'),
                'SourceName': log_data.get('SourceName', 'N/A'),
                'ComputerName': log_data.get('ComputerName', 'N/A'),
                'Channel': log_data.get('Channel', 'N/A'),
                'Message': log_data.get('Message', 'N/A'),
                'timestamp': log_data.get('timestamp', datetime.utcnow().isoformat()),
                'EventCategory': log_data.get('EventCategory', 'N/A'),
                'RecordNumber': log_data.get('RecordNumber', 'N/A')
            }

            # Clean up the message by removing extra newlines and spaces
            if formatted_log['Message']:
                formatted_log['Message'] = formatted_log['Message'].replace('\r\n', ' ').strip()

            if logs_collection is None:
                logger.warning("MongoDB not available, logs will be printed to console")
                logger.info(f"Log entry: {formatted_log}")
            else:
                # Store in MongoDB
                result = logs_collection.insert_one(formatted_log)
                logger.info(f"Inserted {result.inserted_id} into MongoDB")
            
            # Add to queue for SSE
            await log_queue.put(formatted_log)
            logger.info(f"Added log to queue: {formatted_log}")
        
        return JSONResponse(status_code=200, content={"message": f"Processed {len(logs_to_process)} logs successfully"})
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing log: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error processing log: {str(e)}")

@app.get("/logs/count")
async def get_log_count():
    """Get the count of logs in the database"""
    if logs_collection is None:
        raise HTTPException(status_code=500, detail="MongoDB connection is not available")
    
    try:
        count = logs_collection.count_documents({})
        return {"count": count}
    except Exception as e:
        logger.error(f"Error counting logs: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error counting logs: {str(e)}")

# Entry point for running the server
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)