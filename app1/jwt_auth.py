import jwt
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed


class JWTAuth:
    def __init__(self, user: get_user_model()):
        self.user = user

    def generate_token(self):
        payload = {
            'userId': self.user.id,
            'email': self.user.email,
        }

        token = jwt.encode(payload, 'secret', algorithm="HS256")
        return token

    @staticmethod
    def decode_token(request) -> get_user_model():
        token = request.META.get('HTTP_AUTHORIZATION')

        if not token:
            raise AuthenticationFailed('No auth token found')

        token = token.split()

        if token[0] != "Bearer":
            raise AuthenticationFailed('Bad auth token')

        try:
            payload = jwt.decode(token[1], 'secret', algorithms="HS256")

        except:
            raise AuthenticationFailed('Unauthenticated !')

        user = get_user_model().objects.filter(id=payload['userId']).first()
        if not user:
            raise AuthenticationFailed('No user found!')

        return user
