import json
from channels.generic.websocket import AsyncWebsocketConsumer

class SnortConsoleConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def send_console_output(self, event):
        console_output = event['output']
        await self.send(text_data=json.dumps({'output': console_output}))