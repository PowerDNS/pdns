#!/usr/bin/python3
"""Load settings definitions and generates the corresponding documentation."""
import os
import re
import sys
import tempfile
import yaml

def quote(arg):
    """Return a quoted string"""
    return '"' + arg + '"'

def get_vector_sub_type(rust_type):
    return rust_type[4:-1]

def is_vector_of(rust_type):
    return rust_type.startswith('Vec<')

def is_type_native(rust_type):
    if is_vector_of(rust_type):
        sub_type = get_vector_sub_type(rust_type)
        return is_type_native(sub_type)
    return rust_type in ['bool', 'u8', 'u16', 'u32', 'u64', 'f64', 'String']

def get_definitions_from_file(def_file):
    with open(def_file, 'rt', encoding="utf-8") as fd:
        definitions = yaml.safe_load(fd.read())
        return definitions

def get_rust_object_name(name):
    object_name = ''
    capitalize = True
    for char in name:
        if char == '-':
            capitalize = True
            continue
        if capitalize:
            char = char.upper()
            capitalize = False
        object_name += char

    return object_name

def get_definitions_grouped_by_section(def_file):
    sections = {}
    objects = {}
    definitions = get_definitions_from_file(def_file)
    for definition_name, keys in definitions.items():
        if not 'section' in keys:
            object_name = get_rust_object_name(definition_name) + 'Configuration'
            objects[object_name] = keys
            continue
        section_name = keys['section']
        if section_name == 'global':
            sections[definition_name] = keys
        else:
            if not section_name in sections:
                sections[section_name] = {}
            sections[section_name][definition_name] = keys

    return (sections, objects)

def rust_type_to_human_str(rust_type):
    if is_vector_of(rust_type):
        return 'Sequence of ' + rust_type_to_human_str(get_vector_sub_type(rust_type))
    if rust_type in ['u8', 'u32', 'u64']:
        return 'Unsigned integer'
    if rust_type == 'f64':
        return 'Double'
    if rust_type == 'bool':
        return 'Boolean'
    return rust_type

def print_structure(parameters):
    for parameter in parameters:
        print(f'{parameter["name"]}')
        print('^'*len(parameter["name"]))
        print('')

        ptype = parameter['type']
        if is_type_native(ptype):
            ptype = rust_type_to_human_str(ptype)
            print(f'- {ptype}')
        else:
            print(f'- :ref:`{ptype} <setting-yaml-{ptype}>`')

        if 'default' in parameter:
            default = parameter['default']
            if default is True:
                print('')
                continue
            if default == '':
                print(f'- Default: ""')
            else:
                print(f'- Default: {default}')
        else:
            print('- Required')
        print('')
        if 'description' in parameters:
            description = parameters['description']
            print(description)
            print(' ')

def process_section(section_name, entries, objects):
    print(section_name)
    print('=' * len(section_name))
    print('')

    if not 'parameters' in entries:
        if not 'type' in entries:
            for sub_section, sub_entries in sorted(entries.items()):
                process_section(sub_section, sub_entries, objects)
        elif is_vector_of(entries['type']):
            sub_type = get_vector_sub_type(entries['type'])
            if is_type_native(sub_type):
                print(f'- Sequence of {sub_type} objects')
            else:
                print(f'- Sequence of :ref:`{sub_type} <setting-yaml-{sub_type}>` objects')
            print('')

    else:
        if 'type' in entries:
            if entries['type'] != 'list':
                print(f'Section {section_name} has parameters and a type which is not list!', file=sys.stderr)
                return
            else:
                print(f'- Sequence of objects containing:')
                print('')

        parameters = entries['parameters']
        print_structure(parameters)
    print('')

    if 'description' in entries:
        description = entries['description']
        print(description)
        print(' ')

def process_object(object_name, entries):
    print(f'.. _setting-yaml-{object_name}:\n\n')
    process_section(object_name, entries, {})

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/definitions/file>')
        sys.exit(1)

    (sections, objects) = get_definitions_grouped_by_section(sys.argv[1])
    for section_name, entries in sorted(sections.items()):
        process_section(section_name, entries, objects)

    print("@@@@ OBJECTS @@@@")
    for object_name, entries in sorted(objects.items()):
        process_object(object_name, entries)

if __name__ == '__main__':
    main()
