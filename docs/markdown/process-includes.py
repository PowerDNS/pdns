#!/usr/bin/env python

"""
Pandoc filter to process code blocks with class "include" and
replace their content with the included file
"""

from pandocfilters import toJSONFilter, CodeBlock


def code_include(key, value, format, meta):
    if key == 'CodeBlock':
        [[ident, classes, namevals], code] = value
        if code.startswith('!!include='):
            source_file = code.split('=')[1]
            with open(source_file, 'rb') as content_file:
                content = content_file.read()
                content.decode('utf-8')
            return CodeBlock([ident, classes, namevals], content)

if __name__ == "__main__":
    toJSONFilter(code_include)
