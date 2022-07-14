from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CustomUser, Groups, Request, ConnectionRequest, Chats
from .serializer import UserSerializer, GroupSerializer, RequestSerializer, ConnectionSerializer, GetChatsSerializer, \
    ChatSerializer
from .jwt_auth import JWTAuth


def bad_request():
    response = Response()
    response.data = {
        "error": {"enMessage": "Bad request!"}
    }
    response.status_code = 400

    return response


class SignupView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)

        if not serializer.is_valid():
            return bad_request()

        user = serializer.create(serializer.validated_data)
        authentication = JWTAuth(user)
        token = authentication.generate_token()
        response = Response()
        response.data = {
            'token': token,
            'message': "successful"
        }
        response.status_code = 200
        return response


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email', None)
        password = request.data.get('password', None)

        if not (email and password):
            return bad_request()

        user = CustomUser.objects.filter(email=email).first()

        if not user:
            return bad_request()

        if not user.check_password(password):
            return bad_request()

        auth = JWTAuth(user)
        data = {
            "token": auth.generate_token(),
            "message": "successful"
        }
        response = Response(data=data, status=200)

        return response


class GroupsView(APIView):
    def get(self, request):
        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()
        serializer = GroupSerializer(Groups.objects.all(), many=True)
        data = {
            'groups': serializer.data
        }
        return Response(data, 200)

    def post(self, request):
        serializer = GroupSerializer(data=request.data)
        if not serializer.is_valid():
            return bad_request()

        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        if user.group is not None:
            return bad_request()
        data = serializer.validated_data
        data['admin'] = user
        group: Groups = serializer.create(data)
        user.group = group
        user.group_rule = 'owner'
        user.save()
        data = {
            "group": {
                "id": str(group.id)
            },
            "message": "successful"
        }
        response = Response(data, 200)
        return response


class MyGroupView(APIView):
    def get(self, request):
        try:
            user: CustomUser = JWTAuth.decode_token(request)
        except:
            return bad_request()

        user_group = user.group

        if not user_group:
            return bad_request()

        group_members = CustomUser.objects.filter(group_id=user_group.id)
        data = {
            "group": {
                "name": user_group.name,
                "description": user_group.description,
                "members": UserSerializer(group_members, many=True).data
            }
        }
        response = Response(data=data, status=200)
        return response


class RequestsView(APIView):

    def post(self, request):

        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        valid_data = request.data.copy()
        valid_data['userId'] = user.id

        serializer = RequestSerializer(data=valid_data)
        if not serializer.is_valid():
            return bad_request()

        req = serializer.create(serializer.validated_data)

        data = {
            "message": "successful"
        }
        response = Response(data, 200)
        return response

    def get(self, request):
        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        join_requests = Request.objects.filter(userId=user.id)
        serializer = RequestSerializer(join_requests, many=True)
        data = {
            "joinRequests": serializer.data
        }
        response = Response(data=data, status=200)
        return response


class SeeGroupRequestsView(APIView):

    def get(self, request):
        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        user_group = user.group
        rule = user.group_rule
        if user_group is None or rule != 'owner':
            return bad_request()

        req = Request.objects.filter(groupId=user_group.id)

        data = {
            "joinRequests": RequestSerializer(req, many=True).data
        }
        response = Response(data=data, status=200)
        return response


class AcceptRequestView(APIView):
    def post(self, request):
        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        user_group = user.group
        rule = user.group_rule
        if user_group is None or rule != 'owner':
            return bad_request()

        request_id = request.data.get('joinRequestId', None)
        if request_id is None:
            return bad_request()
        req = Request.objects.filter(id=request_id).first()

        if not req:
            return bad_request()

        req_user = CustomUser.objects.get(id=req.userId)
        req_group = Groups.objects.get(id=req.groupId)

        if req_user.group is not None:
            return bad_request()

        req_user.group = req_group
        req_user.group_rule = 'normal'
        req_user.save()

        data = {
            "message": "successful"
        }

        return Response(data, status=200)


class ConnectionRequestsView(APIView):
    def post(self, request):
        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        if user.group_rule != 'owner':
            return bad_request()

        serializer = ConnectionSerializer(data=request.data)

        if not serializer.is_valid():
            return bad_request()

        valid_data = serializer.validated_data
        valid_data['from_group_id'] = user.group.id
        req = serializer.create(valid_data)

        data = {
            "message": "successful"
        }

        response = Response(data=data, status=200)
        return response

    def get(self, request):
        try:
            user = JWTAuth.decode_token(request)
        except:
            return bad_request()

        if user.group_rule != 'owner':
            return bad_request()

        reqs = ConnectionRequest.objects.filter(groupId=user.group.id)

        serializer = ConnectionSerializer(reqs, many=True)
        data = {
            "requests": serializer.data
        }

        return Response(data=data, status=200)


class AcceptConnectionView(APIView):
    def post(self, request):
        try:
            user: CustomUser = JWTAuth.decode_token(request)
        except:
            return bad_request()

        if user.group_rule != 'owner':
            return bad_request()

        group_id = request.data.get('groupId', None)
        if group_id is None:
            return bad_request()

        group = Groups.objects.get(id=group_id)

        user.group.connections.add(Groups.objects.get(id=group_id))
        group.connections.add(user.group)

        data = {
            "message": "successful"
        }

        return Response(data=data, status=200)


class GetChatsViews(APIView):
    def get(self, request):
        try:
            user: CustomUser = JWTAuth.decode_token(request)
        except:
            return bad_request()

        chats = Chats.objects.filter(to_user=user)
        print(chats)
        user_serializer = GetChatsSerializer(chats, many=True)
        data = {
            'chats': user_serializer.data
        }

        return Response(data=data, status=200)



class MessagingView(APIView):
    def post(self, request, user_id: int):
        try:
            user_sender: CustomUser = JWTAuth.decode_token(request)
        except:
            return bad_request()

        user_receiver = CustomUser.objects.get(id=user_id)

        if user_receiver.group is None or user_sender.group is None:
            print('-----------------------------------1')
            return bad_request()

        if not (
                user_receiver.group == user_sender.group or user_sender.group.connections.contains(user_receiver.group)
                or user_receiver.group.connections.contains(user_sender.group)
        ):
            print('-----------------------------------2')
            return bad_request()

        serializer = ChatSerializer(data=request.data)
        if not serializer.is_valid():
            print('-----------------------------------3')
            return bad_request()

        valid_data = serializer.validated_data
        valid_data['to_user'] = user_receiver
        valid_data['from_user'] = user_sender

        message = serializer.create(valid_data)

        data = {
            "message": "successful"
        }

        return Response(data=data, status=200)

    def get(self, request, user_id: int):
        try:
            user: CustomUser = JWTAuth.decode_token(request)
        except:
            return bad_request()

        user_sender = CustomUser.objects.get(id=user_id)

        chats = Chats.objects.filter(
            Q(to_user=user, from_user=user_sender)|Q(to_user=user_sender, from_user=user)
        ).order_by('id').reverse()

        serializer = ChatSerializer(chats, many=True)

        data = {
            'messages': serializer.data
        }
        return Response(data=data, status=200)