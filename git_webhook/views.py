# import hmac
# from hashlib import sha1
#
# from django.conf import settings
# from django.http import HttpResponse, HttpResponseForbidden, HttpResponseServerError
# from django.views.decorators.csrf import csrf_exempt
# from django.views.decorators.http import require_POST
# from django.utils.encoding import force_bytes
#
# import requests
# from ipaddress import ip_address, ip_network
#
# @require_POST
# @csrf_exempt
# def hello(request):
#     # Verify if request came from GitHub
#     forwarded_for = u'{}'.format(request.META.get('HTTP_X_FORWARDED_FOR'))
#     client_ip_address = ip_address(forwarded_for)
#     whitelist = requests.get('https://api.github.com/meta').json()['hooks']
#
#     for valid_ip in whitelist:
#         if client_ip_address in ip_network(valid_ip):
#             break
#     else:
#         return HttpResponseForbidden('Permission denied.')
#
#     # Verify the request signature
#     header_signature = request.META.get('HTTP_X_HUB_SIGNATURE')
#     if header_signature is None:
#         return HttpResponseForbidden('Permission denied.')
#
#     sha_name, signature = header_signature.split('=')
#     if sha_name != 'sha1':
#         return HttpResponseServerError('Operation not supported.', status=501)
#
#     mac = hmac.new(force_bytes(settings.GITHUB_WEBHOOK_KEY), msg=force_bytes(request.body), digestmod=sha1)
#     if not hmac.compare_digest(force_bytes(mac.hexdigest()), force_bytes(signature)):
#         return HttpResponseForbidden('Permission denied.')
#
#     # If request reached this point we are in a good shape
#     # Process the GitHub events
#     event = request.META.get('HTTP_X_GITHUB_EVENT', 'ping')
#
#     if event == 'ping':
#         return HttpResponse('pong')
#     elif event == 'push':
#         # Deploy some code for example
#         return HttpResponse('success')
#
#     # In case we receive an event that's not ping or push
#     return HttpResponse(status=204)
#
import base64
import hashlib

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.conf import settings
import hmac
from hashlib import sha1
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import JSONParser

# @parser_classes((CustomJSONParser,))
class GitWebhook(APIView):
    permission_classes = [AllowAny, ]
    parser_classes = [JSONParser]


    def verifySignature(self, receivedSignature: str, payload):
        WEBHOOK_SECRET = settings.GITHUB_WEBHOOK_KEY
        digest = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).digest()
        e = base64.b64encode(digest).decode()
        if e == receivedSignature:
            return True
        return False
    @csrf_exempt
    def post(self, request, *args, **kwargs):
        body = request.data

        receivedSignature = request.headers.get("typeform-signature")
        if receivedSignature is None:
            return Response({"Fail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        sha_name, signature = receivedSignature.split("=", 1)
        if sha_name != "sha256":
            return Response(
                {"Fail": "Operation not supported."}, status=status.HTTP_501_NOT_IMPLEMENTED
            )
        is_valid = self.verifySignature(signature, request.raw_body)
        if is_valid != True:
            return Response(
                {"Fail": "Invalid signature. Permission denied."}, status=status.HTTP_403_FORBIDDEN
            )
        save_typeform_data(body)
        return Response({}, status=status.HTTP_200_OK)




