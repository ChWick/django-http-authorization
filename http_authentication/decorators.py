from django.http import HttpResponse
from django.contrib.auth import authenticate
import base64


class BasicAuthMiddleware(object):
    @staticmethod
    def unauthorized():
        response = HttpResponse("""<html><title>Auth required</title><body>
                                <h1>Authorization Required</h1></body></html>""", "text/html")
        response['WWW-Authenticate'] = 'Basic realm="Development"'
        response.status_code = 401
        return response

    @staticmethod
    def process_request(request, check_function):
        if 'HTTP_AUTHORIZATION' not in request.META:

            return BasicAuthMiddleware.unauthorized()
        else:
            authentication = request.META['HTTP_AUTHORIZATION']
            (authmeth, auth) = authentication.split(' ', 1)
            if 'basic' != authmeth.lower():
                return BasicAuthMiddleware.unauthorized()

            auth = base64.b64decode(auth.strip()).decode('utf-8')
            username, password = auth.split(':', 1)
            user = authenticate(username=username, password=password)
            if user is not None and check_function(user):
                return None

            return BasicAuthMiddleware.unauthorized()


def http_authorization_login_required(function):
    def check_function(user):
        return user.is_authenticated

    def wrapper(request, *args, **kwargs):
        user = request.user
        if check_function(user):
            return function(request, *args, **kwargs)

        else:
            basic_auth = BasicAuthMiddleware.process_request(request, check_function)
            if basic_auth is None:
                return function(request, *args, **kwargs)

            return basic_auth

    return wrapper


def http_authorization_staff_member_required(function):
    def check_function(user):
        return user.is_authenticated and user.is_active and user.is_staff

    def wrapper(request, *args, **kwargs):
        user = request.user
        if check_function(user):
            return function(request, *args, **kwargs)

        else:
            basic_auth = BasicAuthMiddleware.process_request(request, check_function)
            if basic_auth is None:
                return function(request, *args, **kwargs)

            return basic_auth

    return wrapper
