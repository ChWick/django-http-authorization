# django-http-authorization

This django app adds decorators that fall back to a HTTP_AUTHORIAZATION instead of a django login form.
This can be used for programs that want to interact with your web page but require login.
E. g. to download a password protected file via wget or access an internal icalendar.

The HTTP_AUTHORIZATION relys on `django.contrib.auth.authenticate`.

## Usage

Import the decorators
```
from http_authentication.decorators import http_authorization_staff_member_required, http_authorization_login_required
```
and add it to the view functions
```
@http_authorization_staff_member_required
def protected_view(request):
    return HttpResponse("This page can also be accessed via HTTP_AUTHORIZATION")

```
