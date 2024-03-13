import csv

from django.http import HttpResponse
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.utils.translation import gettext_lazy as _
from django.utils.module_loading import import_string
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.core.exceptions import ObjectDoesNotExist

from allauth.account import app_settings as allauth_account_settings
from allauth.account.views import ConfirmEmailView
from allauth.account.models import EmailAddress
from allauth.account.utils import complete_signup

from dj_rest_auth.utils import jwt_encode
from dj_rest_auth.app_settings import api_settings as app_settings
from dj_rest_auth.models import TokenModel

from rest_framework import status
from rest_framework import filters
from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework.serializers import BaseSerializer, Serializer
from rest_framework.request import Request
from rest_framework.exceptions import MethodNotAllowed

from rest_framework_simplejwt.views import api_settings
from rest_framework_simplejwt.authentication import AUTH_HEADER_TYPES
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from borderless.utils.logger import LOGGER
from borderless.utils.exceptions import ObjectNotFoundException
from borderless.utils.pagination import CustomPagination
from borderless.utils.serializers import CustomErrorSerializer


from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    ResendEmailVerificationSerializer,
    VerifyEmailSerializer,
    UserSerializer,
)

User = get_user_model()
sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters("password1", "password2"),
)

sensitive_post_parameters_m2 = method_decorator(
    sensitive_post_parameters(
        "password",
        "old_password",
        "new_password1",
        "new_password2",
    ),
)


class TokenViewBase(CreateModelMixin, GenericViewSet):
    """
    This base view handles the generation of authentication tokens.

    Attributes:
    - `permission_classes` (tuple): A tuple of permission classes indicating the
      permissions required to access this viewset. In this case, it is set to an
      empty tuple, allowing unrestricted access.
    - `authentication_classes` (tuple): A tuple of authentication classes indicating
      the authentication methods to be used. In this case, it is set to an empty tuple,
      meaning no authentication is required.
    - `serializer_class` (class): The serializer class responsible for validating
      and processing the token generation data.
    - `_serializer_class` (str): The string representation of the serializer class
      used when `serializer_class` is not explicitly set.
    - `www_authenticate_realm` (str): The realm for WWW-Authenticate header.

    Methods:
    - `get_serializer_class`: Get the serializer class to be used for token generation.
    - `get_authenticate_header`: Get the WWW-Authenticate header.
    - `create`: Handle the HTTP POST request for generating authentication tokens
      and returning the new password upon successful submission.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/token/
    Content-Type: application/json

    {
        "username": "example_user",
        "password": "securepassword"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 200 OK
    {
        "detail": "Tokens generated",
        "tokenData": {
            "access": "your_access_token_here",
            "refresh": "your_refresh_token_here"
        }
    }
    ```
    """

    permission_classes = ()
    authentication_classes = ()

    serializer_class = None
    _serializer_class = ""

    www_authenticate_realm = "api"

    def get_serializer_class(self) -> Serializer:
        """
        Get the serializer class to be used for token generation.

        If `serializer_class` is set, use it directly. Otherwise, get the class from settings.

        Returns:
        - Serializer: The serializer class.

        Raises:
        - ImportError: If the serializer class cannot be imported.

        """

        if self.serializer_class:
            return self.serializer_class
        try:
            return import_string(self._serializer_class)
        except ImportError:
            msg = "Could not import serializer '%s'" % self._serializer_class
            raise ImportError(msg)

    def get_authenticate_header(self, request: Request) -> str:
        """
        Get the WWW-Authenticate header.

        Args:
        - `request (Request)`: The HTTP request object.

        Returns:
        - str: The WWW-Authenticate header.

        """
        return '{} realm="{}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(
            data={"detail": "Tokens generated", "tokenData": serializer.validated_data}, status=status.HTTP_200_OK
        )


class TokenObtainPairViewset(TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """

    _serializer_class = api_settings.TOKEN_OBTAIN_SERIALIZER


class TokenRefreshViewset(TokenViewBase):
    """
    **Token Refresh Viewset**

    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.

    Attributes:
    - `_serializer_class` (str): The class responsible for serializing the data
      for token refresh.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/token-refresh/
    Content-Type: application/json

    {
        "refresh": "your_refresh_token_here",
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 200 OK
    {
        "access": "your-access-token"
    }
    ```
    """

    _serializer_class = api_settings.TOKEN_REFRESH_SERIALIZER


class PasswordResetViewset(CreateModelMixin, GenericViewSet):
    """
    **Password Reset Viewset**

    This viewset handles the initiation of the password reset process.

    Attributes:
    - `serializer_class` (class): The serializer class responsible for validating
      and processing the password reset data.
    - `permission_classes` (tuple): A tuple of permission classes indicating the
      permissions required to access this viewset. In this case, it is set to allow
      unrestricted access for password reset.
    - `throttle_scope` (str): The scope identifier for rate limiting.

    Methods:
    - `create`: Handle the HTTP POST request for initiating the password reset process.

    Allowed Methods:
    - **POST**: Initiate the password reset process.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/password/reset/
    Content-Type: application/json

    {
        "email": "user@example.com"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 200 OK
    {
        "detail": "Password reset e-mail has been sent."
    }
    ```
    """

    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)
    throttle_scope = "dj_rest_auth"

    def create(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        # Return the success message with OK HTTP status
        return Response(
            {"detail": _("Password reset e-mail has been sent.")},
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmViewset(CreateModelMixin, GenericViewSet):
    """
    **Password Reset Confirmation Viewset**

    Confirm the password reset e-mail link and reset the user's password.

    Attributes:
    - `serializer_class` (class): The serializer class responsible for validating
      and processing the password reset confirmation data.
    - `permission_classes` (tuple): A tuple of permission classes indicating the
      permissions required to access this viewset. In this case, the `AllowAny`
      permission is used to allow unrestricted access.
    - `throttle_scope` (str): The scope identifier for rate limiting.

    Methods:
    - `dispatch`: Override the dispatch method to apply `sensitive_post_parameters_m`
      decorator.
    - `create`: Handle the HTTP POST request for confirming the password reset link
      and resetting the user's password.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/password/reset/confirm/
    Content-Type: application/json

    {
        "token": "your_reset_token_here",
        "uid": "your_user_id_here",
        "new_password1": "new_secure_password",
        "new_password2": "new_secure_password"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 200 OK
    {
        "detail": "Password has been reset with the new password."
    }
    ```
    """

    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)
    throttle_scope = "dj_rest_auth"

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @csrf_exempt
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": _("Password has been reset with the new password.")},
        )


class PasswordChangeViewset(CreateModelMixin, GenericViewSet):
    """
    **Password Change Viewset**

    Calls Django Auth SetPasswordForm save method.

    Attributes:
    - `serializer_class` (class): The serializer class responsible for validating
      and processing the password change data.
    - `permission_classes` (tuple): A tuple of permission classes indicating the
      permissions required to access this viewset. In this case, the `IsAuthenticated`
      permission is used to allow access only to authenticated users.
    - `throttle_scope` (str): The scope identifier for rate limiting.

    Methods:
    - `dispatch`: Override the dispatch method to apply `sensitive_post_parameters_m`
      decorator.
    - `create`: Handle the HTTP POST request for changing the user's password.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/password/change/
    Content-Type: application/json
    Authorization: Bearer your_access_token_here

    {
        "new_password1": "new_secure_password",
        "new_password2": "new_secure_password"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 201 CREATED
    {
        "detail": "New password has been saved."
    }
    ```
    """

    serializer_class = PasswordChangeSerializer
    permission_classes = (IsAuthenticated,)
    throttle_scope = "dj_rest_auth"

    @sensitive_post_parameters_m
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @csrf_exempt
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": _("New password has been saved.")})


class UserLoginViewset(CreateModelMixin, GenericViewSet):
    """
    **User Login Viewset**

    Check the credentials and return the REST Token if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID in the Django session framework.

    Attributes:
    - `permission_classes` (list): A list of permission classes indicating the permissions required to access this viewset.
      In this case, the `AllowAny` permission is used to allow unrestricted access.
    - `serializer_class` (class): The serializer class responsible for validating and processing the login data.
    - `throttle_scope` (str): The scope identifier for rate limiting.
    - `throttle_classes` (list): A list of throttle classes to apply to the viewset.

    Methods:
    - `dispatch`: Override the dispatch method to apply `sensitive_post_parameters_m2` decorator.
    - `process_login`: Calls Django Auth login method to register User ID in the Django session framework.
    - `get_response_serializer`: Get the appropriate response serializer based on the authentication method.
    - `login`: Perform the login process, including generating authentication tokens.
    - `get_response`: Get the response based on the authentication method.
    - `create`: Handle the HTTP POST request for user login.

    Allowed Methods:
    - **POST**: Check credentials and return the REST Token.

    Example Request:

    ```http
    POST /api/v1/auth/login/
    Content-Type: application/json

    {
        "username": "example_user",
        "password": "securepassword"
    }
    ```

    Example Response:

    ```http
    HTTP/1.1 200 OK
    {
        "user": {
            "id": 1,
            "username": "example_user",
            "email": "user@example.com"
            # ... other user fields ...
        },
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh": "your_refresh_token_here",
        "access_expiration": "2023-01-01T00:00:00Z",
        "refresh_expiration": "2023-01-02T00:00:00Z"
    }
    ```
    """

    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    throttle_scope = "dj_rest_auth"
    throttle_classes = [UserRateThrottle]

    user = None
    access_token = None
    token = None

    @sensitive_post_parameters_m2
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def process_login(self):
        django_login(self.request, self.user)

    def get_response_serializer(self):
        if app_settings.USE_JWT:
            if app_settings.JWT_AUTH_RETURN_EXPIRATION:
                response_serializer = app_settings.JWT_SERIALIZER_WITH_EXPIRATION
            else:
                response_serializer = app_settings.JWT_SERIALIZER

        else:
            response_serializer = app_settings.TOKEN_SERIALIZER
        return response_serializer

    def login(self):
        self.user = self.serializer.validated_data["user"]
        token_model = TokenModel

        if app_settings.USE_JWT:
            self.access_token, self.refresh_token = jwt_encode(self.user)
        elif token_model:
            self.token = app_settings.TOKEN_CREATOR(token_model, self.user, self.serializer)

        if app_settings.SESSION_LOGIN:
            self.request.session["mfa_verified"] = True
            self.process_login()

    def get_response(self):
        serializer_class = self.get_response_serializer()

        if app_settings.USE_JWT:
            from rest_framework_simplejwt.settings import (
                api_settings as jwt_settings,
            )

            access_token_expiration = timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME
            refresh_token_expiration = timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME
            return_expiration_times = app_settings.JWT_AUTH_RETURN_EXPIRATION
            auth_httponly = app_settings.JWT_AUTH_HTTPONLY

            data = {
                "user": self.user,
                "access": self.access_token,
            }

            if not auth_httponly:
                data["refresh"] = self.refresh_token
            else:
                # Wasnt sure if the serializer needed this
                data["refresh"] = ""

            if return_expiration_times:
                data["access_expiration"] = access_token_expiration
                data["refresh_expiration"] = refresh_token_expiration

            serializer = serializer_class(
                instance=data,
                context=self.get_serializer_context(),
            )
        elif self.token:
            serializer = serializer_class(
                instance=self.token,
                context=self.get_serializer_context(),
            )
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)

        response = Response(serializer.data, status=status.HTTP_200_OK)
        if app_settings.USE_JWT:
            from dj_rest_auth.jwt_auth import set_jwt_cookies

            set_jwt_cookies(response, self.access_token, self.refresh_token)
        return response

    def create(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        self.login()
        return self.get_response()


class LogoutViewset(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "dj_rest_auth"

    def get(self, request, *args, **kwargs):
        if getattr(settings, "ACCOUNT_LOGOUT_ON_GET", False):
            response = self.logout(request)
        else:
            response = self.http_method_not_allowed(request, *args, **kwargs)

        return self.finalize_response(request, response, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.logout(request)

    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass

        if app_settings.SESSION_LOGIN:
            django_logout(request)

        response = Response(
            {"detail": _("Successfully logged out.")},
            status=status.HTTP_200_OK,
        )

        if app_settings.USE_JWT:
            # NOTE: this import occurs here rather than at the top level
            # because JWT support is optional, and if `USE_JWT` isn't
            # True we shouldn't need the dependency
            from rest_framework_simplejwt.exceptions import TokenError
            from rest_framework_simplejwt.tokens import RefreshToken

            from dj_rest_auth.jwt_auth import unset_jwt_cookies

            cookie_name = app_settings.JWT_AUTH_COOKIE

            unset_jwt_cookies(response)

            if "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS:
                # add refresh token to blacklist
                try:
                    token = RefreshToken(request.data["refresh"])
                    token.blacklist()
                except ObjectDoesNotExist:
                    raise ObjectNotFoundException
                except KeyError:
                    # response.data = {"detail": _("Refresh token was not included in request data.")}
                    response.status_code = status.HTTP_401_UNAUTHORIZED
                    custom_response = {
                        "error_code": "Refresh_Token_Missing",
                        "error_message": _("Refresh token was not included in request data."),
                    }
                    error_serializer = CustomErrorSerializer(data=custom_response)
                    error_serializer.is_valid(raise_exception=True)
                    response.data = error_serializer.data
                except (TokenError, AttributeError, TypeError) as error:
                    if hasattr(error, "args"):
                        if "Token is blacklisted" in error.args or "Token is invalid or expired" in error.args:
                            # response.data = {"detail": _(error.args[0])}
                            response.status_code = status.HTTP_401_UNAUTHORIZED
                            custom_response = {
                                "error_code": (
                                    "Token_is_blacklisted"
                                    if "Token is blacklisted" in error.args
                                    else "Token_is_invalid_or_expired"
                                ),
                                "error_message": error.args[0],
                            }
                            error_serializer = CustomErrorSerializer(data=custom_response)
                            error_serializer.is_valid(raise_exception=True)
                            response.data = error_serializer.data
                        else:
                            # response.data = {"detail": _("An error has occurred.")}
                            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
                            custom_response = {
                                "error_code": "Unknown_Error",
                                "error_message": _("An error has occurred."),
                            }
                            error_serializer = CustomErrorSerializer(data=custom_response)
                            error_serializer.is_valid(raise_exception=True)
                            response.data = error_serializer.data
                    else:
                        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
                        custom_response = {
                            "error_code": "Unknown_Error",
                            "error_message": _("An error has occurred."),
                        }
                        error_serializer = CustomErrorSerializer(data=custom_response)
                        error_serializer.is_valid(raise_exception=True)
                        response.data = error_serializer.data
            elif not cookie_name:
                message = _(
                    "Neither cookies or blacklist are enabled, so the token "
                    "has not been deleted server side. Please make sure the token is deleted client side.",
                )
                response.data = {"detail": message}
                response.status_code = status.HTTP_200_OK
        return response


class RegisterViewset(CreateModelMixin, GenericViewSet):
    """
    **Viewset for User Registration**

    This viewset handles the registration of users, creating a new user instance.
    The registration process includes sending a verification email when required,
    generating authentication tokens, and completing the user signup.

    Attributes:
    - `serializer_class` (class): The serializer class responsible for validating
      and processing the registration data.
    - `permission_classes` (list): A list of permission classes indicating the
      permissions required to access this viewset. In this case, the `AllowAny`
      permission is used to allow unrestricted access.
    - `token_model` (class): The model class for authentication tokens.
    - `throttle_scope` (str): The scope identifier for rate limiting.
    - `throttle_classes` (list): A list of throttle classes to apply to the viewset.

    Methods:
    - `dispatch`: Override the dispatch method to apply `sensitive_post_parameters_m`
      decorator.
    - `get_response_data`: Get the response data based on the registration settings.
    - `create`: Handle the HTTP POST request for user registration.
    - `perform_create`: Perform the creation of the user instance and handle token generation.

    Allowed Methods:
    - **POST**: Register a new user.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/registration/
    Content-Type: application/json

    {
        "username": "example_user",
        "email": "user@example.com",
        "password": "securepassword"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 201 Created
    {
        "detail": "Registration completed",
        "userData": {
            "user": {
                "id": 1,
                "username": "example_user",
                "email": "user@example.com"
                # ... other user fields ...
            },
            "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh": "your_refresh_token_here"
        }
    }
    ```
    """

    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    token_model = TokenModel
    throttle_scope = "dj_rest_auth"
    throttle_classes = [UserRateThrottle]

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        """
        Override the dispatch method to apply the sensitive_post_parameters_m decorator.
        This decorator marks specific form fields as sensitive, preventing them from
        being logged.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Response: The HTTP response object.

        """
        return super().dispatch(*args, **kwargs)

    def get_response_data(self, user):
        """
        Get the response data based on the registration settings.

        If email verification is mandatory, a message about the verification email
        being sent is returned. If JWT is used for authentication, the user data along
        with access and refresh tokens is returned. If session login is active, None
        is returned. Otherwise, the token data is returned.

        Args:
            user (User): The user instance created during registration.

        Returns:
            dict or None: The response data.

        """
        if allauth_account_settings.EMAIL_VERIFICATION == allauth_account_settings.EmailVerificationMethod.MANDATORY:
            return {"detail": _("Verification e-mail sent.")}

        if app_settings.USE_JWT:
            data = {
                "user": user,
                "access": self.access_token,
                "refresh": self.refresh_token,
            }
            return app_settings.JWT_SERIALIZER(data, context=self.get_serializer_context()).data
        elif app_settings.SESSION_LOGIN:
            return None
        else:
            return app_settings.TOKEN_SERIALIZER(user.auth_token, context=self.get_serializer_context()).data

    def create(self, request, *args, **kwargs):
        """
        **Create Method**

        Handle the HTTP POST request for user registration.

        This method processes the registration data, performs validation, creates a new
        user instance, and generates the appropriate response.

        Args:
        - `request (Request)`: The HTTP request object.
        - `*args`: Variable length argument list.
        - `**kwargs`: Arbitrary keyword arguments.

        Returns:
        - `Response`: The HTTP response object.

        Allowed Methods:
        - `POST`: Register a new user.

        Example Request:
        ----------------
        ```http
        POST /api/v1/auth/registration/
        Content-Type: application/json

        {
            "username": "example_user",
            "email": "user@example.com",
            "password": "securepassword"
        }
        ```

        Example Response:
        ----------------
        ```http
        HTTP/1.1 201 Created
        {
            "detail": "Registration completed",
            "userData": {
                "user": {
                    "id": 1,
                    "username": "example_user",
                    "email": "user@example.com"
                    # ... other user fields ...
                },
                "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh": "your_refresh_token_here"
            }
        }
        ```

        """
        serializer = self.get_serializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        data = self.get_response_data(user)

        if data:
            response = Response(
                data=data,
                status=status.HTTP_201_CREATED,
                headers=headers,
            )
        else:
            response = Response(status=status.HTTP_204_NO_CONTENT, headers=headers)

        return response

    def perform_create(self, serializer):
        """
        Perform the creation of the user instance and handle token generation.

        This method is responsible for creating the user instance and handling
        token generation based on the registration settings.

        Args:
            serializer (RegisterSerializer): The serializer instance.

        Returns:
            User: The created user instance.

        """
        user = serializer.save(self.request)
        if allauth_account_settings.EMAIL_VERIFICATION != allauth_account_settings.EmailVerificationMethod.MANDATORY:
            if app_settings.USE_JWT:
                self.access_token, self.refresh_token = jwt_encode(user)
            elif not app_settings.SESSION_LOGIN:
                # Session authentication isn't active either, so this has to be
                #  token authentication
                app_settings.TOKEN_CREATOR(self.token_model, user, serializer)

        complete_signup(
            self.request._request,
            user,
            allauth_account_settings.EMAIL_VERIFICATION,
            None,
        )
        return user


class VerifyEmailViewset(APIView, ConfirmEmailView):
    """
    **Verify Email ViewSet**

    This viewset handles the verification of email addresses.

    Attributes:
    - `permission_classes` (tuple): A tuple of permission classes indicating the permissions required to access this viewset.
      In this case, the `AllowAny` permission is used to allow unrestricted access.
    - `allowed_methods` (tuple): A tuple of HTTP methods allowed for this viewset.
    - `serializer_class` (class): The serializer class responsible for validating and processing the verification data.

    Methods:
    - `get_serializer`: Get the serializer instance.
    - `create`: Handle the HTTP POST request for email verification.

    Allowed Methods:
    - **POST**: Verify the email address.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/verify-email/
    Content-Type: application/json

    {
        "key": "your_confirmation_key_here"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 200 OK
    {
        "detail": "ok"
    }
    ```
    """

    permission_classes = [AllowAny]
    allowed_methods = ("POST", "OPTIONS", "HEAD")
    throttle_classes = [UserRateThrottle]

    def get(self, *args, **kwargs):
        raise MethodNotAllowed("GET")

    def get_serializer(self, *args, **kwargs):
        """
        Get the serializer instance.

        Returns:
            VerifyEmailSerializer: The serializer instance.

        """
        return VerifyEmailSerializer(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.kwargs["key"] = serializer.validated_data["key"]
        confirmation = self.get_object()
        confirmation.confirm(self.request)
        return Response({"detail": _("ok")}, status=status.HTTP_200_OK)


class ResendEmailVerificationViewset(CreateModelMixin, GenericViewSet):
    """
    **Resend Email Verification**

    This viewset allows users to resend the email verification link.

    Attributes:
    - `permission_classes` (list): A list of permission classes indicating the
      permissions required to access this viewset. In this case, the `AllowAny`
      permission is used to allow unrestricted access.
    - `serializer_class` (class): The serializer class responsible for validating
      and processing the data required for resending the email verification.
    - `queryset` (QuerySet): The queryset representing the collection of email
      addresses.
    - `throttle_classes` (list): A list of throttle classes to apply to the viewset.

    Methods:
    - `create`: Handle the HTTP POST request for resending the email verification link.

    Allowed Methods:
    - **POST**: Resend the email verification link.

    Example Request:
    ----------------
    ```http
    POST /api/v1/auth/resend-email-verification/
    Content-Type: application/json

    {
        "email": "user@example.com"
    }
    ```

    Example Response:
    ----------------
    ```http
    HTTP/1.1 200 OK
    {
        "detail": "ok"
    }
    ```
    """

    permission_classes = [AllowAny]
    serializer_class = ResendEmailVerificationSerializer
    queryset = EmailAddress.objects.all()
    throttle_classes = [UserRateThrottle]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = self.get_queryset().filter(**serializer.validated_data).first()
        if email and not email.verified:
            email.send_confirmation(request)

        return Response({"detail": _("ok")}, status=status.HTTP_200_OK)

class CheckUserViewSet(ListModelMixin, GenericViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    permission_classes = [AllowAny]

    def get_queryset(self, *args, **kwargs):
        return self.queryset

    @action(detail=False, methods=["GET"], url_path="check-user-exists")
    def check_user_exists(self, request):
        """
        Check if a user exists by email in the cached users.
        """
        email = request.query_params.get("email")

        if not email:
            return Response({"detail": "Email is a required field."}, status=status.HTTP_200_OK)

        # Retrieve users from the cache
        cached_users = cache.get('users', [])

        # Check if any user with the specified email exists in the cached users
        for user in cached_users:
            if user.email == email and user.is_staff:
                return Response({"detail": f"A user already exists with this credential: {email}"}, status=status.HTTP_200_OK)
            elif user.email == email and not user.is_staff:
                return Response({"detail": f"You are not a staff to access login"}, status=status.HTTP_200_OK)
        return Response({"detail": f"Ok."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["GET"], url_path="check-phone-exists")
    def check_phone_number_exists(self, request):
        """
        Check if a user exists by email in the cached users.
        """
        phone = request.query_params.get("phone")

        if not phone:
            return Response({"detail": "Phone Number is a required field."}, status=status.HTTP_200_OK)

        # Retrieve users from the cache
        cached_users = cache.get('users', [])

        # Check if any user with the specified email exists in the cached users
        for user in cached_users:
            if user.phone == phone and user.is_staff:
                return Response({"detail": f"A user already exists with this credential: {phone}"}, status=status.HTTP_200_OK)
            elif user.phone == phone and not user.is_staff:
                return Response({"detail": f"You are not a staff to access login"}, status=status.HTTP_200_OK)
        return Response({"detail": f"Ok."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["GET"], url_path="export-csv")
    def export_waiters_csv(self, request):
        from io import StringIO
        """
        Export all waiters records as a CSV file.
        Example usage: /api/users/export-csv/
        """
        if not request.user.is_staff:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        # Create a StringIO object to hold the CSV data
        csv_buffer = StringIO()

        queryset = User.objects.filter(waitlisted=True)  # Assuming waiters are staff members


        # Create a CSV writer and write the header
        csv_writer = csv.writer(csv_buffer)
        csv_writer.writerow(
            ["ID", "NAME", "MOBILE NUMBER", "EMAIL ADDRESS", "COUNTRY OF RESIDENCE"]
        )  # Add other fields as needed

        # Write user data to the CSV file
        for user in queryset:
            csv_writer.writerow(
                [user.id, user.name, user.phone, user.email, user.country]
            )  # Add other field values as needed

        # Get the CSV data from the buffer
        csv_data = csv_buffer.getvalue().encode("utf-8")
        response = HttpResponse(csv_data, content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="waiters.csv"'
        LOGGER.info(response)

        return response

class UserViewSet(RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        assert isinstance(self.request.user.id, int)
        return self.queryset.filter(id=self.request.user.id)

    @action(detail=False)
    def me(self, request):
        serializer = UserSerializer(request.user, context={"request": request})
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    @action(detail=False, methods=["GET", "POST"])
    def waiters(self, request):
        from django.db.models import Q

        if not request.user.is_staff:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        if request.method == "GET":
            query_param = self.request.query_params.get("q", None)

            queryset = User.objects.filter(waitlisted=True)
            if query_param is not None:
                queryset = User.objects.filter(waitlisted=True).filter(
                    Q(name__icontains=query_param) | Q(email__icontains=query_param)
                )
            serializer = UserSerializer(queryset, many=True, context={"request": request})
            return Response(status=status.HTTP_200_OK, data=serializer.data)

        serializer = UserSerializer(data=request.data, context={"request": request})

        if serializer.is_valid():
            # Assuming the user is identified by the 'user_id' in the request data
            user = User.objects.create(waitlisted=True, **serializer.data)
            password = User.objects.make_random_password()
            user.set_password(password)
            user.save(update_fields=['password'])

            # Assuming you have a related model for responses, adjust as needed
            return Response(status=status.HTTP_201_CREATED)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)




def email_confirm_redirect(request, key):
    return HttpResponseRedirect(f"{settings.EMAIL_CONFIRM_REDIRECT_BASE_URL}{key}/")


def password_reset_confirm_redirect(request, uidb64, token):
    return HttpResponseRedirect(f"{settings.PASSWORD_RESET_CONFIRM_REDIRECT_BASE_URL}{uidb64}/{token}/")
