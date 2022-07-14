from rest_framework import serializers
from .models import CustomUser, Groups, Request, ConnectionRequest, Chats


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'name', 'email', 'group_rule', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        name = validated_data.get('name')
        email = validated_data.get('email')
        password = validated_data.get('password')
        user = self.Meta.model.objects.create_user(
            name=name,
            email=email,
            password=password
        )
        return user


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Groups
        fields = ['id', 'name', 'description']


class RequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = ['id', 'userId', 'groupId', 'date']


class ConnectionSerializer(serializers.ModelSerializer):
    connectionRequestId = serializers.IntegerField(source='id', read_only=True)
    sent = serializers.DateTimeField(source='date', read_only=True)

    class Meta:
        model = ConnectionRequest
        fields = ['connectionRequestId', 'groupId', 'sent']


class GetChatsSerializer(serializers.ModelSerializer):
    userId = serializers.IntegerField(source='from_user.id')
    name = serializers.CharField(source='from_user.name')

    class Meta:
        model = Chats
        fields = ['userId', 'name']

class ChatSerializer(serializers.ModelSerializer):

    class Meta:
        model = Chats
        fields = ['message', 'date', 'from_user']
