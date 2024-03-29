import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.utils.timesince import timesince

from .serializers import UserSerializer
from .models import Message, ChatRoom
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        print("++++Chat++++")
        self.room_group_name = f"chat_{self.room_id}"
        print("self.room_group_name = ",self.room_group_name)
        # Add the channel to the room's group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        # Accept the WebSocket connection
        await self.accept()
        # Send a connection message to the client

    async def disconnect(self, close_code):
        # Remove the channel from the room's group upon disconnect
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        user = self.scope["user"]
        user_serializer = UserSerializer(user)
        email = user_serializer.data['email']

        new_message = await self.create_message(self.room_id, message, email)
        
        # Send the received message to the room's group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'room_id': self.room_id,
                'sender_email': email,
                'created': timesince(new_message.timestamp),
            }
        )

    async def chat_message(self, event):
        message = event['message']
        room_id = event['room_id']
        email = event['sender_email']
        created = event['created']

        # Send the chat message to the WebSocket
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': message,
            'room_id': room_id,
            'sender_email': email,
            'created': created,
        }))

    @sync_to_async
    def create_message(self, room_id, message, email):
        user = User.objects.get(email=email)
        room = ChatRoom.objects.get(id=room_id) 
        message = Message.objects.create(content=message, room=room, sender=user)
        message.save()
        return message
