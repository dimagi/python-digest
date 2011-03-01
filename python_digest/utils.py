try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from http import parse_quoted_string, parse_token

import logging

# Make sure a NullHandler is available
# This was added in Python 2.7/3.2
try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

l = logging.getLogger(__name__)
l.addHandler(NullHandler())
l.setLevel(logging.DEBUG)

_LWS=[chr(9), ' ', '\r', '\n']
_ILLEGAL_TOKEN_CHARACTERS = (
    [chr(n) for n in range(0-31)] + # control characters
    [chr(127)] + # DEL
    ['(',')','<','>','@',',',';',':','\\','"','/','[',']','?','=','{','}',' '] +
    [chr(9)]) # horizontal tab

class State(object):
    def character(self, c):
        return self.consume(c)

    def close(self):
        return self.eof()

    def eof(self):
        raise ValueError('EOF not permitted in this state.')

    '''
    Return False to keep the current state, or True to pop it
    '''
    def consume(c):
        raise Execption('Unimplemented')

class ParentState(State):
    def __init__(self):
        super(State, self).__init__()
        self.child = None

    def close(self):
        if self.child:
            return self.handle_child_return(self.child.close())
        else:
            return self.eof()
        
    def push_child(self, child, c=None):
        self.child = child
        if c is not None:
            return self.send_to_child(c)
        else:
            return False

    def send_to_child(self, c):
        return self.handle_child_return(self.child.character(c))

    def handle_child_return(self, returned_value):
        if returned_value:
            child = self.child
            self.child = None
            return self.child_complete(child)
        return False

    '''
    Return False to keep the current state, or True to pop it.
    '''
    def child_complete(self, child):
        return False

    def character(self, c):
        if self.child:
            return self.send_to_child(c)
        else:
            return self.consume(c)
    
    def consume(self, c):
        return False
                
        
class EscapedCharacterState(State):
    def __init__(self, io):
        super(EscapedCharacterState, self).__init__()
        self.io = io

    def consume(self, c):
        self.io.write(c)
        return True

class KeyTrailingWhitespaceState(State):
    def consume(self, c):
        if c in _LWS:
            return False
        elif c == '=':
            return True
        else:
            raise ValueError("Expected whitespace or '='")

class ValueLeadingWhitespaceState(ParentState):
    def __init__(self, io):
        super(ValueLeadingWhitespaceState, self).__init__()
        self.io = io
        
    def consume(self, c):
        if c in _LWS:
            return False
        elif c == '"':
            return self.push_child(QuotedValueState(self.io))
        elif c in _ILLEGAL_TOKEN_CHARACTERS:
            raise ValueError('The character %r is not a legal token character' % c)
        else:
            self.io.write(c)
            return self.push_child(UnquotedValueState(self.io))

    def child_complete(self, child):
        return True

class ValueTrailingWhitespaceState(State):
    def eof(self):
        return True

    def consume(self, c):
        if c in _LWS:
            return False
        elif c == ',':
            return True
        else:
            raise ValueError("Expected whitespace, ',', or EOF")

class BaseQuotedState(ParentState):
    def __init__(self, io):
        super(BaseQuotedState, self).__init__()
        self.key_io = io

    def consume(self, c):
        if c == '\\':
            return self.push_child(EscapedCharacterState(self.key_io))
        elif c == '"':
            return self.push_child(self.TrailingWhitespaceState())
        else:
            self.key_io.write(c)
            return False
        
    def child_complete(self, child):
        if type(child) == EscapedCharacterState:
            return False
        elif type(child) == self.TrailingWhitespaceState:
            return True

class BaseUnquotedState(ParentState):
    def __init__(self, io):
        super(BaseUnquotedState, self).__init__()
        self.io = io

    def consume(self, c):
        if c == self.terminating_character:
            return True
        elif c in _LWS:
            return self.push_child(self.TrailingWhitespaceState())
        elif c in _ILLEGAL_TOKEN_CHARACTERS:
            raise ValueError('The character %r is not a legal token character' % c)
        else:
            self.io.write(c)
            return False
        
    def child_complete(self, child):
        # type(child) == self.TrailingWhitespaceState
        return True
    
class QuotedKeyState(BaseQuotedState):
    TrailingWhitespaceState = KeyTrailingWhitespaceState

class QuotedValueState(BaseQuotedState):
    TrailingWhitespaceState = ValueTrailingWhitespaceState

class UnquotedKeyState(BaseUnquotedState):
    TrailingWhitespaceState = KeyTrailingWhitespaceState
    terminating_character = '='

class UnquotedValueState(BaseUnquotedState):
    TrailingWhitespaceState = ValueTrailingWhitespaceState
    terminating_character  = ','

    def eof(self):
        return True

class NewPartState(ParentState):
    def __init__(self, parts):
        super(NewPartState, self).__init__()
        self.parts = parts
        self.key_io = StringIO()
        self.value_io = StringIO()

    def consume(self, c):
        if c in _LWS:
            return False
        elif c == '"':
            return self.push_child(QuotedKeyState(self.key_io))
        elif c in _ILLEGAL_TOKEN_CHARACTERS:
            raise ValueError('The character %r is not a legal token character' % c)
        else:
            self.key_io.write(c)
            return self.push_child(UnquotedKeyState(self.key_io))

    def child_complete(self, child):
        if type(child) in [QuotedKeyState, UnquotedKeyState]:
            return self.push_child(ValueLeadingWhitespaceState(self.value_io))
        else:
            self.parts[self.key_io.getvalue()] = self.value_io.getvalue()
            return True

class FoundationState(ParentState):
    def __init__(self, defaults):
        super(FoundationState, self).__init__()
        self.parts = defaults.copy()

    def result(self):
        return self.parts

    def consume(self, c):
        return self.push_child(NewPartState(self.parts), c)

def parse_parts(parts_string, defaults={}):
    
    state_machine = FoundationState(defaults)
    index = 0
    try:
        for c in parts_string:
            state_machine.character(c)
            index += 1
        state_machine.close()
        return state_machine.result()
    except ValueError, e:
        annotated_parts_string = "%s[%s]%s" % (parts_string[0:index],
                                               index < len(parts_string) and parts_string[index] or '',
                                               index + 1 < len(parts_string) and parts_string[index+1:] or '')
        l.exception("Failed to parse the Digest string "
                    "(offending character is in []): %r" % annotated_parts_string)
        return None

def format_parts(**kwargs):
    return ", ".join(['%s="%s"' % (k,v.encode('utf-8')) for (k,v) in kwargs.items()])
