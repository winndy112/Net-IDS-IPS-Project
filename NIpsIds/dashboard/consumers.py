import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
import logging
from pathlib import Path
import aiofiles
import os

logger = logging.getLogger(__name__)

class SnortConsoleConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.info("WebSocket connection attempt")
        try:
            await self.accept()
            logger.info("WebSocket connected successfully")
            
            # Start monitoring the log file
            asyncio.create_task(self.monitor_log_file())
            
        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            raise

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnected with code: {close_code}")

    async def monitor_log_file(self):
        log_file = "log/alert_fast/alert_fast.txt"
        
        try:
            # Get initial file size
            file_size = os.path.getsize(log_file)
            
            while True:
                try:
                    current_size = os.path.getsize(log_file)
                    
                    if current_size > file_size:
                        async with aiofiles.open(log_file, mode='r') as f:
                            # Seek to previous position
                            await f.seek(file_size)
                            
                            # Read new content
                            new_content = await f.read()
                            
                            # Update file size
                            file_size = current_size
                            
                            # Send each new line
                            for line in new_content.splitlines():
                                if line.strip():
                                    await self.send(text_data=json.dumps({
                                        'output': line
                                    }))
                    
                    # Wait before next check
                    await asyncio.sleep(0.1)  # Check every 100ms
                    
                except FileNotFoundError:
                    logger.error(f"Log file not found: {log_file}")
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.error(f"Error monitoring log file: {str(e)}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            logger.error(f"Fatal error in monitor_log_file: {str(e)}")