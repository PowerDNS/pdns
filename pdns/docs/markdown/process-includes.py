#!/usr/bin/env python

"""
Pandoc filter to process code blocks with class "include" and
replace their content with the included file
"""

from pandocfilters import toJSONFilter, CodeBlock


def code_include(key, value, format, meta):
    if key == 'CodeBlock':
        [[ident, classes, namevals], code] = value
        for nameval in namevals:
            if nameval[0] == 'include':
                with open(nameval[1], 'rb') as content_file:
                    content = content_file.read()
                    content.decode('utf-8')
                namevals.remove(nameval)
                return CodeBlock([ident, classes, namevals], content)

if __name__ == "__main__":
    toJSONFilter(code_include)
