from rest_framework import pagination
from rest_framework.response import Response
from urllib.parse import urlencode

class CustomPagination(pagination.PageNumberPagination):
    """
    Custom pagination class that generates pagination links with query parameters.

    Example usage:
        Suppose you have an API endpoint '/api/data' that returns paginated data.
        To fetch data using pagination query parameters, make a GET request like this:

        GET /api/data?p=2&page_size=10

        This request will fetch the second page of data with 10 items per page.
        The 'p' parameter specifies the page number, and 'page_size' parameter specifies
        the number of items per page. Adjust the URL and query parameters according to
        your API endpoint and requirements.
    """

    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 50
    page_query_param = 'p'

    def get_next_link(self):
        """
        Generates the URL for the next page.
        """
        if not self.page.has_next():
            return None
        url = self.request.build_absolute_uri()
        page_number = self.page.next_page_number()
        query_params = self.request.query_params.copy()
        query_params[self.page_query_param] = page_number
        url += '?' + urlencode(query_params)
        return url

    def get_previous_link(self):
        """
        Generates the URL for the previous page.
        """
        if not self.page.has_previous():
            return None
        url = self.request.build_absolute_uri()
        page_number = self.page.previous_page_number()
        query_params = self.request.query_params.copy()
        if page_number == 1:
            del query_params[self.page_query_param]
        else:
            query_params[self.page_query_param] = page_number
        url += '?' + urlencode(query_params)
        return url

    def get_paginated_response(self, data):
        """
        Returns paginated response with pagination links and current page number.
        """
        return Response(
            {
                'count': self.page.paginator.count,
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'current_page': self.page.number,
                'results': data
            }
        )
