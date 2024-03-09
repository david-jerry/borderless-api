from typing import Any, Dict, Optional, Union
from rest_framework.exceptions import APIException
from rest_framework import status
from rest_framework.views import exception_handler
from rest_framework import exceptions, status
from rest_framework.response import Response

from .logger import LOGGER

from django.utils.translation import gettext_lazy as _


from .serializers import CustomErrorSerializer

def custom_exception_handler(exc: APIException, context: Optional[dict] = {}):
    """
    Custom exception handler for formatting APIException responses.

    This handler transforms standard DRF exception responses into a custom format
    containing an 'error_code' and 'error_message'.

    Args:
    exc (APIException): The raised APIException.
    context (dict): Additional context information about the exception.

    Returns:
    Response: A formatted response containing 'error_code' and 'error_message'.
    """
    try:
        response = exception_handler(exc, context)

        if response is not None:
            custom_response = {
                'error_code': response.data.get('code', status.HTTP_500_INTERNAL_SERVER_ERROR),
                'error_message': response.data.get('detail', str(exc)),
            }
            error_serializer = CustomErrorSerializer(data=custom_response)
            error_serializer.is_valid(raise_exception=True)
            response.data = error_serializer.data

        return response
    except Exception as e:
        LOGGER.error(str(e))
        return Response(
            {
                'error_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'error_message': str(e),
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # try:
    #     response = exception_handler(exc, context)

    #     if response is not None:
    #         LOGGER.info(response.data)
    #         custom_response = {
    #             'error_code': response.data['code'],
    #             'error_message': response.data['detail'] if response.data['detail'] else str(exc),
    #         }
    #         error_serializer = CustomErrorSerializer(data=custom_response)
    #         error_serializer.is_valid(raise_exception=True)
    #         response.data = error_serializer.data

    #     return response
    # except Exception as e:
    #     LOGGER.error(str(e))
    #     return Response(
    #         {
    #             'error_code': 500,
    #             'error_message': str(e)
    #         },
    #         status=status.HTTP_500_INTERNAL_SERVER_ERROR
    #     )


class EmailAlreadyExistsException(APIException):
    """
    Exception raised for an attempt to create an account with an existing email address.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when detecting an attempt
        to create an account with an email that already exists:

        ```python
        from rest_framework.views import exception_handler

        def create_user(email):
            if user_already_exists(email):
                raise EmailAlreadyExistsException()
            # Continue with user creation logic
        ```

    In this example, if the `user_already_exists` function determines that the email
    already exists, the `EmailAlreadyExistsException` is raised to handle this specific
    case.
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Email address is already used by another account.'
    default_code = 'DuplicateEmail'

class VPNDetectedException(APIException):
    """
    Exception raised when a vpn has been detected by a users ip.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when detecting an attempt
        to access the website while a vpn is connected:

        ```python
        from rest_framework.views import exception_handler

        def create_user(email):
            if user_already_exists(email):
                raise EmailAlreadyExistsException()
            # Continue with user creation logic
        ```

    In this example, if the `user_already_exists` function determines that the email
    already exists, the `EmailAlreadyExistsException` is raised to handle this specific
    case.
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'VPN Detected. Please access this page without using a VPN.'
    default_code = 'VPNDetected'


class UnAuthenticatedUserOrExistsException(APIException):
    """
    Exception raised for an attempt to create an account with an existing email address.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when detecting an attempt
        to create an account with an email that already exists:

        ```python
        from rest_framework.views import exception_handler

        def create_user(email):
            if user_already_exists(email):
                raise EmailAlreadyExistsException()
            # Continue with user creation logic
        ```

    In this example, if the `user_already_exists` function determines that the email
    already exists, the `EmailAlreadyExistsException` is raised to handle this specific
    case.
    """
    status_code = status.HTTP_204_NO_CONTENT
    default_detail = 'This user is not authenticated or perhaps, does not even exist. Try authenticating and if the error persist then the user does not exists.'
    default_code = 'UnAuthenticatedOrMissingUser'


class MFAException(APIException):
    """
    Exception raised when Multi-Factor Authentication (MFA) is required.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when detecting the need
        for Multi-Factor Authentication:

        ```python
        from rest_framework.views import exception_handler

        def some_function():
            if mfa_required():
                raise MFAException()
            # Continue with your logic
        ```

        In this example, if the `mfa_required` function determines that Multi-Factor
        Authentication is required, the `MFAException` is raised to handle this specific case.
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Multi-Factor Authentication is required. Try reauthenticating your session to fix this, or else contact support: support@anjochow.com'
    default_code = 'MFARequired'


class TokenExpiredException(APIException):
    """
    Exception raised when the authentication token has expired and needs refreshing.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when detecting an expired token:

        ```python
        from rest_framework.views import exception_handler

        def some_function():
            if token_has_expired():
                raise TokenExpiredException()
            # Continue with your logic
        ```

        In this example, if the `token_has_expired` function determines that the token has
        expired, the `TokenExpiredException` is raised to handle this specific case.
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'The authentication token has expired. Please refresh the token.'
    default_code = 'TokenExpired'


class ObjectNotFoundException(APIException):
    """
    Exception raised when an object cannot be found in the database.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when querying for an object:

        ```python
        from rest_framework.views import exception_handler

        def get_object_by_id(object_id):
            try:
                return YourModel.objects.get(id=object_id)
            except YourModel.DoesNotExist:
                raise ObjectNotFoundException(f"The object with ID {object_id} does not exist.")
        ```

        In this example, if the `YourModel.objects.get(id=object_id)` query fails to find
        the object, the `ObjectNotFoundException` is raised with a specific error message.
    """
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'The requested object was not found in the database.'
    default_code = 'ObjectNotFound'

class InsufficientBalanceException(APIException):
    """
    Exception raised when a requested balance is insufficient.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when querying for an object:

        ```python
        from rest_framework.views import exception_handler

        def get_object_by_id(object_id):
            try:
                return YourModel.objects.get(id=object_id)
            except YourModel.DoesNotExist:
                raise ObjectNotFoundException(f"The object with ID {object_id} does not exist.")
        ```

        In this example, if the `YourModel.objects.get(id=object_id)` query fails to find
        the object, the `ObjectNotFoundException` is raised with a specific error message.
    """
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'The requested accoutn balance is insufficient to complete the transaction.'
    default_code = 'InsufficientBalance'


class UnauthorizedException(APIException):
    """
    Exception raised for unauthorized access.

    Attributes:
        status_code (int): The HTTP status code for the exception.
        default_detail (str): The default error message.
        default_code (str): The default error code.

    Example:
        To use this exception in your code, you can raise it when unauthorized access is detected:

        ```python
        from rest_framework.views import exception_handler

        def some_function():
            if unauthorized_condition():
                raise UnauthorizedException()
            # Continue with your logic
        ```

        In this example, if the `unauthorized_condition` function determines that unauthorized access
        has occurred, the `UnauthorizedException` is raised to handle this specific case.
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'You are not allowed to access the website with your current email and username. Please try registering a new account'
    default_code = 'unauthorized'

class UnauthorizedObjectException(APIException):
    """
    Exception raised when a user attempts to access an object or perform an action
    for which they do not have the required permissions.

    Attributes:
    - `status_code` (int): The HTTP status code for the exception. Defaults to 401 (Unauthorized).
    - `default_detail` (str): A default human-readable error message providing details about
      the unauthorized access. Defaults to 'You are not allowed to view this request response.'
    - `default_code` (str): A default error code indicating the type of exception. Defaults to 'unauthorized.'
    """

    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'You are not allowed to perform any action with this endpoint. Possible reason could be due to the object requested not belonging to you.'
    default_code = 'unauthorized'


