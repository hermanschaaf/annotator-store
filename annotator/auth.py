import datetime
import json

import iso8601
import jwt

DEFAULT_TTL = 86400

class Consumer(object):
    def __init__(self, key):
        self.key = key

class User(object):
    def __init__(self, id, consumer, is_admin):
        self.id = id
        self.consumer = consumer
        self.is_admin = is_admin

    @classmethod
    def from_token(cls, token):
#KHOR: Add: Start
        consumer_obj = Consumer(token['consumerKey'])
        consumer_obj.secret = '6E1C924B-C03B-4F7F-0000-B72EE2338B39'
        consumer_obj.ttl = DEFAULT_TTL
#KHOR: Add: End
        return cls(
            token['userId'],
#KHOR            Consumer(token['consumerKey']),
            consumer_obj,
            token.get('admin', False)
        )

class Authenticator(object):
    """
    A wrapper around the low-level encode_token() and decode_token() that is
    backend inspecific, and swallows all possible exceptions thrown by badly-
    formatted, invalid, or malicious tokens.
    """

    def __init__(self, consumer_fetcher):
        """
        Arguments:
        consumer_fetcher -- a function which takes a consumer key and returns an object
                            with 'key', 'secret', and 'ttl' attributes
        """
        self.consumer_fetcher = consumer_fetcher

    def request_user(self, request):
        """
        Retrieve the user object associated with the current request.

        Arguments:
        request -- a Flask Request object

        Returns: a user object
        """
        token = self._decode_request_token(request)
        print("[auth.pz, request_user] request:" + str(request))
        print("[auth.pz, request_user] request.headers:" + str(request.headers))
        print("[auth.pz, request_user] request.cookies:" + str(request.cookies))
        print("[auth.pz, request_user] token:" + str(token))

        if token:
            try:
                print("[auth.pz, request_user] User.from_token(token):" + str(User.from_token(token)))
                return User.from_token(token)
            except KeyError:
                return None
        else:
            return None

    def _decode_request_token(self, request):
        """
        Retrieve any request token from the passed request, verify its
        authenticity and validity, and return the parsed contents of the token
        if and only if all such checks pass.

        Arguments:
        request -- a Flask Request object
        """

        token = request.headers.get('x-annotator-auth-token')
        print("[decode_request_token] token:" + str(token))
        if token is None:
            return False

        try:
            unsafe_token = decode_token(token, verify=False)
        except TokenInvalid: # catch junk tokens
            return False
        print("[decode_request_token] unsafe_token:" + str(unsafe_token))

        key = unsafe_token.get('consumerKey')
        print("[decode_request_token] key:" + str(key))
        if not key:
            return False

        consumer = self.consumer_fetcher(key)
        print("[decode_request_token] consumer:" + str(consumer))
        if not consumer:
            return False

        print("[decode_request_token] consumer.secret:" + str(consumer.secret))
        print("[decode_request_token] consumer.ttl:" + str(consumer.ttl))
        try:
            return decode_token(token, secret=consumer.secret, ttl=consumer.ttl)
        except TokenInvalid: # catch inauthentic or expired tokens
            return False

class TokenInvalid(Exception):
    pass

# Main auth routines
def encode_token(token, secret):
    token.update({'issuedAt': _now().isoformat()})
    return jwt.encode(token, secret)

def decode_token(token, secret='', ttl=DEFAULT_TTL, verify=True):
    print("[decode_token] token:" + str(token) + ", secret:" + str(secret) + ", verify:" + str(verify))
    try:
        token = jwt.decode(token, secret, verify=verify)
    except jwt.DecodeError:
        import sys
        exc_class, exc, tb = sys.exc_info()
        new_exc = TokenInvalid("error decoding JSON Web Token: %s" % exc or exc_class)
        raise new_exc.__class__, new_exc, tb

    print("[decode_token] token:" + str(token))
    if verify:
        issue_time = token.get('issuedAt')
        if issue_time is None:
            raise TokenInvalid("'issuedAt' is missing from token")

        issue_time = iso8601.parse_date(issue_time)
        expiry_time = issue_time + datetime.timedelta(seconds=ttl)

        if issue_time > _now():
            raise TokenInvalid("token is not yet valid")
        if expiry_time < _now():
            raise TokenInvalid("token has expired")

    return token

def _now():
    return datetime.datetime.now(iso8601.iso8601.UTC).replace(microsecond=0)
