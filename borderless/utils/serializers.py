from rest_framework import serializers

class CustomErrorSerializer(serializers.Serializer):
    error_code = serializers.CharField()
    error_message = serializers.CharField()
