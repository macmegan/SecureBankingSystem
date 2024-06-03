from rest_framework.response import Response
from rest_framework import status

def make_success_response(optional_data = None):
    return Response(optional_data or {}, status=status.HTTP_201_CREATED)

def make_error_response(errors):
    return Response({
        'errors': errors
    }, status=status.HTTP_400_BAD_REQUEST)