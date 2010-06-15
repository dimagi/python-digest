import unittest

import StringIO

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
    def test_validate_uri(self):
        self.assertTrue(validate_uri('http://server:port/some/path', '/some/path'))
        self.assertTrue(validate_uri('/some/path', '/some/path'))
        self.assertTrue(validate_uri('http://server:port/some/path?q=v&x=y', '/some/path'))
        self.assertTrue(validate_uri('http://server:port/spacey%20path', '/spacey path'))
        self.assertTrue(validate_uri('http://server:port/%7euser/', '/~user/'))
        self.assertTrue(validate_uri('http://server:port/%7Euser/', '/~user/'))
        self.assertFalse(validate_uri('http://server:port/some/other/path', '/some/path'))
        self.assertFalse(validate_uri('/some/other/path', '/some/path'))
        self.assertFalse(validate_uri('http://server:port/some/other/path?q=v&x=y',
                                      '/some/path'))

    def test_nonce_functions(self):
        timestamp = 12345.01
        nonce = calculate_nonce(timestamp, 'secret')
        self.assertTrue(validate_nonce(nonce, 'secret'))
        self.assertFalse(validate_nonce(nonce, 'other secret'))
        self.assertFalse(validate_nonce(nonce[:-1], 'secret'))
        self.assertEqual(timestamp, get_nonce_timestamp(nonce))

    def test_parse_digest_challenge(self):
        challenge_header = 'Digest nonce="1263312775.17:7a4267d73fb67fe9da897bb5445153ae", ' \
            'realm="API", algorithm="MD5", opaque="38A924C1874E52F9A379BCA9F64D04F6", ' \
            'qop="auth", stale="false"'
        self.assertTrue(is_digest_challenge(challenge_header))
        self.assertFalse(is_digest_challenge('Basic realm="API"'))
        digest_challenge = parse_digest_challenge(challenge_header)
        
        self.assertEqual('1263312775.17:7a4267d73fb67fe9da897bb5445153ae',
                         digest_challenge.nonce)
        self.assertEqual('API', digest_challenge.realm)
        self.assertEqual('MD5', digest_challenge.algorithm)
        self.assertEqual('38A924C1874E52F9A379BCA9F64D04F6', digest_challenge.opaque)
        self.assertEqual('auth', digest_challenge.qop)
        self.assertEqual(False, digest_challenge.stale)

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
        # One calling pattern
        request_header = build_authorization_request(
            username='erik', realm='API', method='GET',
            uri='/api/accounts/account/erik/',
            nonce='1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc',
            opaque='D80E5E5109EB9918993B5F886D14D2E5', nonce_count=3,
            password='test', client_nonce='c316b5722463aee9')

        self.assertTrue(is_digest_credential(request_header))

        digest_response = parse_digest_credentials(request_header)

        self.assertEqual(digest_response.username, 'erik')
        self.assertEqual(digest_response.qop, 'auth')
        self.assertEqual(digest_response.algorithm, 'MD5')
        self.assertEqual(digest_response.uri, '/api/accounts/account/erik/')
        self.assertEqual(digest_response.nonce,
                         '1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc')
        self.assertEqual(digest_response.opaque, 'D80E5E5109EB9918993B5F886D14D2E5')
        self.assertEqual(digest_response.realm, 'API')
        self.assertEqual(digest_response.response, 'a8f5c1289e081a7a0f5faa91d24f3b46')
        self.assertEqual(digest_response.nc, 3)
        self.assertEqual(digest_response.cnonce, 'c316b5722463aee9')
        
        # Second calling pattern
        challenge_header = \
            'Digest nonce="1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc", ' \
            'realm="API", algorithm="MD5", opaque="D80E5E5109EB9918993B5F886D14D2E5", ' \
            'qop="auth", stale="false"'

        digest_challenge = parse_digest_challenge(challenge_header)
        request_header = build_authorization_request(username='erik', method='GET',
                                                     uri='/api/accounts/account/erik/',
                                                     nonce_count=3, password='test',
                                                     digest_challenge=digest_challenge)
        self.assertTrue(is_digest_credential(request_header))

        digest_response = parse_digest_credentials(request_header)

        self.assertEqual(digest_response.nonce,
                         '1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc')
        self.assertEqual(digest_response.realm, 'API')
        self.assertEqual(digest_response.opaque, 'D80E5E5109EB9918993B5F886D14D2E5')

        # Third calling pattern
        challenge_header = \
            'Digest nonce="1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc", ' \
            'realm="API", algorithm="MD5", opaque="D80E5E5109EB9918993B5F886D14D2E5", ' \
            'qop="auth", stale="false"'

        request_header = build_authorization_request(username='erik', method='GET',
                                                     uri='/api/accounts/account/erik/',
                                                     nonce_count=3, password='test',
                                                     digest_challenge=challenge_header)
        digest_response = parse_digest_credentials(request_header)
        self.assertEqual(digest_response.nonce,
                         '1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc')

    def test_unicode_credentials(self):
        username = u"mickey\xe8\xe9"
        challenge_header = \
            'Digest nonce="1263251163.72:0D93:6c012a9bc11e535ff2cddb54663e44bc", ' \
            'realm="API", algorithm="MD5", opaque="D80E5E5109EB9918993B5F886D14D2E5", ' \
            'qop="auth", stale="false"'
        request_header = build_authorization_request(
            username=username, method='GET', uri='/api/accounts/account/erik/',
            nonce_count=3,password=username, digest_challenge=challenge_header)
        digest_response = parse_digest_credentials(request_header)
        self.assertEqual(digest_response.username, 'mickey\xc3\xa8\xc3\xa9')

        kd = calculate_request_digest(
            'GET', calculate_partial_digest(username, 'API', username),
            digest_response)
        self.assertEquals(digest_response.response, kd)
        

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
    def test_parse_parts_with_embedded_comma(self):
        valid_parts = ('username="wikiphoto", realm="API", '
                       'nonce="1268201053.67:5140:070c3f060614cbe244e1a713768e0211", '
                       'uri="/api/for/wikiphoto/missions/missions/Oh, the Memories/", '
                       'response="d9fb4f9882386339931cf088c74f3942", '
                       'opaque="11861771750D1B343DF11FE4C223725A", '
                       'algorithm="MD5", cnonce="17ec1ffae9e01d125d65accef45157fa", '
                       'nc=00000061, qop=auth')

        self.assertEquals("/api/for/wikiphoto/missions/missions/Oh, the Memories/",
                          parse_parts(valid_parts)['uri'])

    def test_parse_parts_with_escaped_quote(self):
        valid_parts = ('username="wiki\\"photo"')

        self.assertEquals("wiki\"photo",
                          parse_parts(valid_parts)['username'])

    def test_parse_parts(self):
        valid_parts = ' hello = world , my = " name is sam " '

        self.assertEquals({'hello': 'world', 'my': " name is sam "}, parse_parts(valid_parts))

        invalid_parts = ' hello world , my = " name is sam " '
        self.assertEquals(None, parse_parts(invalid_parts))

        # known issue: ',' or '=' could appear in a quoted-string and would be interpreted as
        # ending the part

        invalid_parts = ' hello=world=goodbye , my = " name is sam " '
        self.assertEquals(None, parse_parts(invalid_parts))

    def test_escaped_character_state(self):
        for c in 'a\\\',"= _-1#':
            io = StringIO()
            ecs = EscapedCharacterState(io)
            self.assertTrue(ecs.character(c))
            self.assertEquals(c, io.getvalue())

    def test_value_leading_whitespace_state_unquoted_value(self):
        io = StringIO()
        vlws = ValueLeadingWhitespaceState(io)
        self.assertFalse(vlws.character(' '))
        self.assertFalse(vlws.character('\r'))
        self.assertFalse(vlws.character('\n'))
        self.assertFalse(vlws.character(chr(9)))
        self.assertFalse(vlws.character(' '))
        self.assertFalse(vlws.character('a'))
        self.assertTrue(vlws.character(','))
        self.assertEquals('a', io.getvalue())

    def test_value_leading_whitespace_state_quoted_value(self):
        io = StringIO()
        vlws = ValueLeadingWhitespaceState(io)
        self.assertFalse(vlws.character(' '))
        self.assertFalse(vlws.character('"'))
        self.assertFalse(vlws.character('\\'))
        self.assertFalse(vlws.character('"'))
        self.assertFalse(vlws.character('"'))
        self.assertTrue(vlws.character(','))
        self.assertEquals('"', io.getvalue())
        
    def test_value_leading_whitespace_state_error(self):
        vlws = KeyTrailingWhitespaceState()
        self.assertFalse(vlws.character(' '))
        self.assertRaises(ValueError, vlws.character, '<')

    def test_key_trailing_whitespace_state(self):
        ktws = KeyTrailingWhitespaceState()
        self.assertFalse(ktws.character(' '))
        self.assertFalse(ktws.character('\r'))
        self.assertFalse(ktws.character('\n'))
        self.assertFalse(ktws.character(chr(9)))
        self.assertFalse(ktws.character(' '))
        self.assertTrue(ktws.character('='))
        
    def test_key_trailing_whitespace_state_error(self):
        for c in 'a,"':
            ktws = KeyTrailingWhitespaceState()
            self.assertFalse(ktws.character(' '))
            self.assertRaises(ValueError, ktws.character, c)
 
    def test_quoted_key_state(self):
        io = StringIO()
        qks = QuotedKeyState(io)
        for c in '\\"this is my string,\\" he said!':
            self.assertFalse(qks.character(c))
        self.assertFalse(qks.character('"'))
        self.assertFalse(qks.character(' '))
        self.assertFalse(qks.character('\r'))
        self.assertTrue(qks.character('='))
        self.assertEquals('"this is my string," he said!', io.getvalue())

    def test_quoted_key_state_eof_error(self):
        io = StringIO()
        qks = QuotedKeyState(io)
        self.assertFalse(qks.character('a'))
        self.assertFalse(qks.character('"'))
        self.assertFalse(qks.character(' '))
        self.assertFalse(qks.character('\r'))
        self.assertRaises(ValueError, qks.close)

    def test_value_trailing_whitespace_state(self):
        vtws = ValueTrailingWhitespaceState()
        self.assertFalse(vtws.character(' '))
        self.assertFalse(vtws.character('\r'))
        self.assertFalse(vtws.character('\n'))
        self.assertFalse(vtws.character(chr(9)))
        self.assertFalse(vtws.character(' '))
        self.assertTrue(vtws.character(','))

    def test_value_trailing_whitespace_state_eof(self):
        vtws = ValueTrailingWhitespaceState()
        self.assertFalse(vtws.character(' '))
        self.assertTrue(vtws.close())

    def test_value_trailing_whitespace_state_error(self):
        for c in 'a="':
            vtws = ValueTrailingWhitespaceState()
            self.assertFalse(vtws.character(' '))
            self.assertRaises(ValueError, vtws.character, c)

    def test_unquoted_key_state_with_whitespace(self):
        io = StringIO()
        uks = UnquotedKeyState(io)
        for c in 'hello_world':
            self.assertFalse(uks.character(c))
        
        self.assertFalse(uks.character(' '))
        self.assertFalse(uks.character('\r'))
        self.assertTrue(uks.character('='))
        self.assertEquals('hello_world', io.getvalue())

    def test_unquoted_key_state_without_whitespace(self):
        io = StringIO()
        uks = UnquotedKeyState(io)
        for c in 'hello_world':
            self.assertFalse(uks.character(c))
        self.assertTrue(uks.character('='))
        self.assertEquals('hello_world', io.getvalue())


    def test_unquoted_key_state_error(self):
        io = StringIO()
        uks = UnquotedKeyState(io)
        self.assertFalse(uks.character('a'))
        self.assertRaises(ValueError, uks.character, '<')

    def test_quoted_value_state(self):
        io = StringIO()
        qvs = QuotedValueState(io)
        for c in '\\"this is my string,\\" he said!':
            self.assertFalse(qvs.character(c))
        self.assertFalse(qvs.character('"'))
        self.assertFalse(qvs.character(' '))
        self.assertFalse(qvs.character('\r'))
        self.assertTrue(qvs.character(','))
        self.assertEquals('"this is my string," he said!', io.getvalue())

    def test_quoted_value_state_eof(self):
        io = StringIO()
        qvs = QuotedValueState(io)
        for c in '\\"this is my string,\\" he said!':
            self.assertFalse(qvs.character(c))
        self.assertFalse(qvs.character('"'))
        self.assertTrue(qvs.close())
        self.assertEquals('"this is my string," he said!', io.getvalue())

    def test_quoted_value_state_error(self):
        io = StringIO()
        qvs = QuotedValueState(io)
        for c in '\\"this is my string,\\" he said!':
            self.assertFalse(qvs.character(c))
        self.assertFalse(qvs.character('"'))
        self.assertRaises(ValueError, qvs.character, '=')

    def test_new_part_state(self):
        # Try a variety of strings, both with comma and eof terminating them
        for ending in (lambda s: s.character(','), lambda s: s.close()):
            parts = {}
            for s in ('hello=world', ' hi = bye ', ' "what?" = "\\"ok\\""'):
                nps = NewPartState(parts)
                for c in s:
                    self.assertFalse(nps.character(c))
                self.assertTrue(ending(nps))
            self.assertEquals(parts, {'hello': 'world',
                                      'hi': 'bye',
                                      'what?': '"ok"'})

    def test_new_part_state_error(self):
        nps = NewPartState(parts={})
        self.assertRaises(ValueError, nps.character, '<')

    def test_foundation_state(self):
        fs = FoundationState({'default': 'value', 'hello': 'bye bye'})
        for c in '  hello=world, my=turn, yes=no , one = 1, " \\"quoted\\" " = unquoted  ':
            self.assertFalse(fs.character(c))
        fs.close()
        self.assertEquals(fs.result(), {'default': 'value',
                                        'hello': 'world',
                                        'my': 'turn',
                                        'yes': 'no',
                                        'one': '1',
                                        ' "quoted" ': 'unquoted'})

    def test_foundation_state_error(self):
        for s in ('', '  ', 'hello', 'hello=', 'hello=world,', 'hello=world, ',
                  'hello=world, a'):
            fs = FoundationState({'default': 'value'})
            for c in s:
                self.assertFalse(fs.character(c))
            self.assertRaises(ValueError, fs.close)
