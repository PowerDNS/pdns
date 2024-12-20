#!/usr/bin/python3
"""Load settings definitions and generates the corresponding documentation."""
import os
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
    global_objects = {}
    definitions = get_definitions_from_file(def_file)
    for definition_name, keys in definitions.items():
        if not 'section' in keys:
            object_name = get_rust_object_name(definition_name) + 'Configuration'
            objects[object_name] = keys
            continue
        section_name = keys['section']
        if 'type' in keys and keys['type'] == 'list':
            object_name = get_rust_object_name(definition_name) + 'Configuration'
            objects[object_name] = keys
            if section_name == 'global':
                global_objects[definition_name] = rust_type_to_human_str(object_name)
            continue
        if section_name == 'global':
            if 'type' in keys and is_type_native(keys['type']):
                sections[definition_name] = keys
            print(definition_name)
            global_objects[definition_name] = rust_type_to_human_str(keys['type'] if 'type' in keys else get_rust_object_name(definition_name) + 'Configuration')
        else:
            if not section_name in sections:
                sections[section_name] = {}
                global_objects[section_name] = rust_type_to_human_str(get_rust_object_name(section_name) + 'Configuration')
            sections[section_name][definition_name] = keys

    return (sections, objects, global_objects)

def rust_type_to_human_str(rust_type):
    if is_vector_of(rust_type):
        return 'Sequence of ' + rust_type_to_human_str(get_vector_sub_type(rust_type))
    if rust_type in ['u8', 'u16', 'u32', 'u64']:
        return 'Unsigned integer'
    if rust_type == 'f64':
        return 'Double'
    if rust_type == 'bool':
        return 'Boolean'
    if rust_type == 'String':
        return 'String'
    return f':ref:`{rust_type} <setting-yaml-{rust_type}>`'

def print_structure(parameters):
    # YAML block first
    output = '.. code-block:: yaml\n\n'
    for parameter in parameters:
        output += f'  {parameter["name"]}: '
        ptype = parameter['type']
        human_type = rust_type_to_human_str(ptype)
        output += f'{human_type}'

        if 'default' in parameter:
            default = parameter['default']
            if default is True:
                output += '\n'
                continue
            if default == '':
                output += ' ("")'
            else:
                output += f' ({default})'
        else:
            output += ' (Required)'
        output += '\n'

    output += '\n\n'

    # then all parameters, one by one
    for parameter in parameters:
        ptype = parameter['type']
        if not is_type_native(ptype):
            continue
        output += f'{parameter["name"]}\n'
        output += '^'*len(parameter["name"]) + '\n'
        output += '\n'

        human_type = rust_type_to_human_str(ptype)
        output += f'- {human_type}\n'

        if 'default' in parameter:
            default = parameter['default']
            if default is True:
                output += '\n'
                continue
            if default == '':
                output += '- Default: ""\n'
            else:
                output += f'- Default: {default}\n'
        else:
            output += '- Required\n'
        output += '\n'
        if 'description' in parameters:
            description = parameters['description']
            output += description
            output += '\n \n'

    return output

def get_section_type(entries):
    pass

def process_section(section_name, entries, prefix=''):
    output = ''

    if not 'parameters' in entries and not 'type' in entries:
        print(f'{section_name} has NEITHER type nor parameters')
        for sub_section, sub_entries in sorted(entries.items()):
            output += process_section(sub_section, sub_entries, prefix=section_name)
        return output

    if prefix:
        output += prefix + '.'
    output += f'{section_name}\n'
    output += '-' * (len(prefix) + (1 if len(prefix) > 0 else 0) + len(section_name)) + '\n'
    output += '\n'

    if not 'parameters' in entries:
        output += rust_type_to_human_str(entries['type']) + '\n'
    else:
        if 'type' in entries:
            if entries['type'] != 'list':
                print(f'Section {section_name} has parameters and a type which is not list!', file=sys.stderr)
                return ''

            output += 'Sequence of objects containing:\n'
            output += '\n'

        parameters = entries['parameters']
        output += print_structure(parameters)
    output += '\n'

    if 'description' in entries:
        description = entries['description']
        output += description + '\n'
        output += ' \n'

    return output

def process_object(object_name, entries):
    output = f'.. _setting-yaml-{object_name}:\n\n'
    output += process_section(object_name, entries)
    return output

def get_temporary_file_for_generated_content(directory):
    generated_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir=directory, delete=False)
    generated_fp.write('.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py\n\n')
    return generated_fp

def process_settings():
    output = '''.. raw:: latex

    \\setcounter{secnumdepth}{-1}

YAML configuration reference
============================

Since 2.0.0, :program:`dnsdist` supports the YAML configuration format in addition to the existing Lua one.

If the configuration file passed to :program:`dnsdist` via the ``-C`` command-line switch ends in ``.yml``, it is assumed to be in the new YAML format, and an attempt toload a Lua configuration file with the same name but the ``.lua`` will be done before loading the YAML configuration. If the names ends in ``.lua``, there will also be an attempt to find a file with the same name but ending in ``.yml``. Otherwise the existing Lua configuration format is assumed.

A YAML configuration file contains several sections, that are described below.

.. code-block:: yaml\n
'''

    (sections, objects, global_objects) = get_definitions_grouped_by_section(sys.argv[1])
    for field_name, human_str in sorted(global_objects.items()):
        output += f'  {field_name}: {human_str}\n'

    output += '\n'

    for section_name, entries in sorted(sections.items()):
        output += process_section(section_name, entries)

    for object_name, entries in sorted(objects.items()):
        output += process_object(object_name, entries)

    return output

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/definitions/file>')
        sys.exit(1)

    generated_fp = get_temporary_file_for_generated_content('../docs/')

    output = process_settings()
#    output += process_selectors()

    generated_fp.write(output)
    os.rename(generated_fp.name, '../docs/reference/yaml.rst')

if __name__ == '__main__':
    main()
