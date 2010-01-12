import unittest

from python_digest import *
from python_digest.http import *
from python_digest.utils import *

class HttpTests(unittest.TestCase):
    def test_parse_quoted_string(self):
        test_cases = [
            ('""', ''), # OK
            ('"hello"', 'hello'), # OK
            ('', False), # no quotes
            ('"', False), # no end-quote
            ('a"', False), # no start-quote
            ('"a', False), # no end-quote
            ('a', False), # no quotes
            ('"\\""', '"'), # escaping quote
            ('"\\\\"', '\\'), # escaping backslash
            ('"hello\\"', False) # no end-quote
            ]

        for test_case in test_cases:
            self.assertEqual(test_case[1], parse_quoted_string(test_case[0]))

    def test_parse_token(self):
        legal_tokens = [
            "hello_world!",
            "hmm.",
            "123-47"]

        illegal_tokens = [
            "tabit\t",
            "a/b",
            "what's up, doc?"]

        for token in legal_tokens:
            self.assertEqual(token, parse_token(token))

        for token in illegal_tokens:
            self.assertFalse(parse_token(token))

class PythonDigestTests(unittest.TestCase):
    def test_nonce_functions(self):
        timestamp = 12345.01
        nonce = calculate_nonce(timestamp, 'secret')
        self.assertTrue(validate_nonce(nonce, 'secret'))
        self.assertFalse(validate_nonce(nonce, 'other secret'))
        self.assertFalse(validate_nonce(nonce[:-1], 'secret'))
        self.assertEqual(timestamp, get_nonce_timestamp(nonce))

    def test_build_digest_challenge(self):
        timestamp = 12345.01
        challenge = build_digest_challenge(timestamp, 'secret', 'myrealm', 'myopaque', False)

        self.assertEqual('digest ', challenge[0:7].lower())

        challenge_parts = parse_parts(challenge[7:])

        self.assertEqual(challenge_parts['realm'], 'myrealm')
        self.assertEqual(challenge_parts['opaque'], 'myopaque')
        self.assertEqual(challenge_parts['qop'], 'auth')

        if 'algorithm' in challenge_parts:
            self.assertEqual(challenge_parts['algorithm'], 'MD5')
        if 'stale' in challenge_parts:
            self.assertEqual(challenge_parts['stale'].lower(), 'false')

        self.assertTrue(validate_nonce(challenge_parts['nonce'], 'secret'))
        self.assertEqual(12345.01, get_nonce_timestamp(challenge_parts['nonce']))

    def test_build_authorization_request(self):
        header = build_authorization_request(
            username='erik', realm='API', method='GET',
            uri='/api/accounts/account/erik/',
            nonce='1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc',
            opaque='D80E5E5109EB9918993B5F886D14D2E5', nonce_count=3,
            password='test', client_nonce='c316b5722463aee9')

        self.assertEqual('digest ', header[0:7].lower())

        header_parts = parse_parts(header[7:])
        self.assertEqual(header_parts['username'], 'erik')
        self.assertEqual(header_parts['qop'], 'auth')
        self.assertEqual(header_parts['algorithm'], 'MD5')
        self.assertEqual(header_parts['uri'], '/api/accounts/account/erik/')
        self.assertEqual(header_parts['nonce'],
                         '1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc')
        self.assertEqual(header_parts['opaque'], 'D80E5E5109EB9918993B5F886D14D2E5')
        self.assertEqual(header_parts['realm'], 'API')
        self.assertEqual(header_parts['response'], 'a8f5c1289e081a7a0f5faa91d24f3b46')
        self.assertEqual(header_parts['nc'], '00000003')
        self.assertEqual(header_parts['cnonce'], 'c316b5722463aee9')
        

    def test_calculate_request_digest(self):
        # one calling pattern
        header = \
            'Digest username="erik", realm="API", ' \
            'nonce="1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc", ' \
            'uri="/api/accounts/account/erik/", algorithm=MD5, ' \
            'response="a8f5c1289e081a7a0f5faa91d24f3b46", ' \
            'opaque="D80E5E5109EB9918993B5F886D14D2E5", qop=auth, nc=00000003, ' \
            'cnonce="c316b5722463aee9"'

        digest_response = parse_digest_credentials(header)
        kd = calculate_request_digest('GET', calculate_partial_digest('erik', 'API', 'test'),
                                      digest_response)
        self.assertEqual(kd, 'a8f5c1289e081a7a0f5faa91d24f3b46')

        # other calling pattern
        kd = calculate_request_digest(
            'GET', calculate_partial_digest('erik', 'API', 'test'),
            nonce='1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc',
            uri='/api/accounts/account/erik/',
            nonce_count=3, client_nonce='c316b5722463aee9')
        self.assertEqual(kd, 'a8f5c1289e081a7a0f5faa91d24f3b46')

    def test_calculate_partial_digest(self):
        self.assertEqual('ecfc9eadfaecf48a1edcf894992350dd',
                         calculate_partial_digest('erik', 'API', 'test'))

    def test_parse_digest_response(self):
        digest_response_string = \
            'username="erik", realm="API", ' \
            'nonce="the_nonce", uri="/the/uri", ' \
            'response="18824d23aa8649c6231978d3e8532528", ' \
            'opaque="the_opaque", ' \
            'qop=auth, nc=0000000a, cnonce="the_cnonce"'

        digest_response = parse_digest_response(digest_response_string)
        self.assertEqual('erik', digest_response.username)
        self.assertEqual('API', digest_response.realm)
        self.assertEqual('the_nonce', digest_response.nonce)
        self.assertEqual('/the/uri', digest_response.uri)
        self.assertEqual('18824d23aa8649c6231978d3e8532528', digest_response.response)
        self.assertEqual('the_opaque', digest_response.opaque)
        self.assertEqual('auth', digest_response.qop)
        self.assertEqual(10, digest_response.nc)
        self.assertEqual('the_cnonce', digest_response.cnonce)
        self.assertEqual('MD5', digest_response.algorithm)

        # missing username
        invalid_digest_response_string = \
            'realm="API", ' \
            'nonce="the_nonce", uri="/the/uri", ' \
            'response="18824d23aa8649c6231978d3e8532528", ' \
            'opaque="the_opaque", ' \
            'qop=auth, nc=0000000a, cnonce="the_cnonce"'

        self.assertEqual(None, parse_digest_response(invalid_digest_response_string))

        # invalid nc
        invalid_digest_response_string = \
            'username="erik", realm="API", ' \
            'nonce="the_nonce", uri="/the/uri", ' \
            'response="18824d23aa8649c6231978d3e8532528", ' \
            'opaque="the_opaque", ' \
            'qop=auth, nc=0000000X, cnonce="the_cnonce"'

        self.assertEqual(None, parse_digest_response(invalid_digest_response_string))

        # invalid quoted-string
        invalid_digest_response_string = \
            'username="erik", realm="API", ' \
            'nonce="the_nonce", uri="/the/uri", ' \
            'response="18824d23aa8649c6231978d3e8532528", ' \
            'opaque="the_opaque", ' \
            'qop=auth, nc=0000000X, cnonce="the_cnonce'

        self.assertEqual(None, parse_digest_response(invalid_digest_response_string))
    def test_is_digest_credential(self):
        header_string = \
            'Digest username="erik", realm="API", ' \
            'nonce="the_nonce", uri="/the/uri", ' \
            'response="18824d23aa8649c6231978d3e8532528", ' \
            'opaque="the_opaque", ' \
            'qop=auth, nc=0000000a, cnonce="the_cnonce"'

        self.assertTrue(is_digest_credential(header_string))

        self.assertFalse(is_digest_credential("Basic A7F="))

    def test_parse_digest_credentials(self):
        header_string = \
            'Digest username="erik", realm="API", ' \
            'nonce="the_nonce", uri="/the/uri", ' \
            'response="18824d23aa8649c6231978d3e8532528", ' \
            'opaque="the_opaque", ' \
            'qop=auth, nc=0000000a, cnonce="the_cnonce"'

        self.assertEqual('erik', parse_digest_credentials(header_string).username)

class UtilsTests(unittest.TestCase):
    def test_parse_part_value(self):
        test_cases = [
            ('"hello"', 'hello'),
            ('a"', False),
            ('"hello\\"', False),
            ("hello_world!", "hello_world!"),
            ("a/b", False)
            ]

        for test_case in test_cases:
            self.assertEqual(test_case[1], parse_part_value(test_case[0]))

    def test_parse_parts(self):
        valid_parts = ' hello = world , my = " name is sam " '

        self.assertEquals({'hello': 'world', 'my': " name is sam "}, parse_parts(valid_parts))

        invalid_parts = ' hello world , my = " name is sam " '
        self.assertEquals(None, parse_parts(invalid_parts))

        # known issue: ',' or '=' could appear in a quoted-string and would be interpreted as
        # ending the part

        invalid_parts = ' hello=world=goodbye , my = " name is sam " '
        self.assertEquals(None, parse_parts(invalid_parts))
