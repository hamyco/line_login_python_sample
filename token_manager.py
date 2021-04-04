import secrets
import base64
import hashlib


# Already satisfied BASE64
def generate(token_length=16):
    return secrets.token_urlsafe(token_length)


# https://tools.ietf.org/html/rfc7636#page-17
# This appendix describes how to implement a base64url-encoding
# function without padding, based upon the standard base64-encoding function that uses padding.
# Requirement
# - base64
# - url safe
def convert2sha256(token):
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode('utf-8')).digest()).decode('utf-8').strip('=')


if __name__ == "__main__":
    before = '123456'
    after = u'jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI'
    converted_value = convert2sha256(before)
    print(converted_value)
    assert (converted_value == after)