_ILLEGAL_TOKEN_CHARACTERS = (
    [chr(n) for n in range(0-31)] + # control characters
    [chr(127)] + # DEL
    ['(',')','<','>','@',',',';',':','\\','"','/','[',']','?','=','{','}',' '] +
    [chr(9)]) # horizontal tab

def parse_quoted_string(quoted_string):
    '''
    Parse a quoted string as defined by RFC 2616 (HTTP/1.1)
    '''
    if (len(quoted_string) < 2 or
        not quoted_string.startswith('"') or
        not quoted_string.endswith('"')):
        return False

    unquoted_value = ""

    is_escaped = False

    for c in quoted_string[1:-1]:
        if is_escaped:
            unquoted_value = unquoted_value + c
            is_escaped = False
        elif c == '\\':
            is_escaped = True
        elif c == '"':
            return False
        else:
            unquoted_value = unquoted_value + c

    if is_escaped:
        return False
    return unquoted_value
    
def parse_token(token):
    '''
    Parse a token as defined by RFC 2616 (HTTP/1.1)
    '''
    for c in token:
        if c in _ILLEGAL_TOKEN_CHARACTERS:
            return False
    else:
        return token
