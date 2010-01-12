from http import parse_quoted_string, parse_token

def parse_part_value(part_value):
    if (part_value.startswith('"')):
        return parse_quoted_string(part_value)
    else:
        return parse_token(part_value)

def parse_parts(parts_string, defaults={}):
    parts = defaults.copy()

    for part in parts_string.split(','):
        part_components = [component.strip() for component in part.split('=',1)]
        if not len(part_components) == 2:
            return None

        name = parse_token(part_components[0])
        if name == False:
            return None

        value = parse_part_value(part_components[1])
        if value == False:
            return None
        
        parts[name] = value

    return parts

def format_parts(**kwargs):
    return ", ".join(['%s="%s"' % (k,v) for (k,v) in kwargs.items()])
