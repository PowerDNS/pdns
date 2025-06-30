#!/usr/bin/python3
"""Load settings definitions and generates the corresponding documentation."""
import os
from pathlib import Path
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
        if char in ['-', '_']:
            capitalize = True
            continue
        if capitalize:
            char = char.upper()
            capitalize = False
        object_name += char

    return object_name

def get_objects(def_file):
    objects = {}
    definitions = get_definitions_from_file(def_file)
    for definition_name, keys in definitions.items():
        object_name = get_rust_object_name(definition_name) + 'Configuration'
        objects[object_name] = keys

    return objects

def rust_type_to_human_str(rust_type, entry_type, generate_ref=True):
    if is_vector_of(rust_type):
        return 'Sequence of ' + rust_type_to_human_str(get_vector_sub_type(rust_type), entry_type, generate_ref)
    if rust_type in ['u8', 'u16', 'u32', 'u64']:
        return 'Unsigned integer'
    if rust_type == 'f64':
        return 'Double'
    if rust_type == 'bool':
        return 'Boolean'
    if rust_type == 'String':
        return 'String'
    if generate_ref:
        return f':ref:`{rust_type} <yaml-{entry_type}-{rust_type}>`'
    return f'{rust_type}'

def print_structure(parameters, entry_type):
    output = ''
    # list
    for parameter in parameters:
        output += f'- **{parameter["name"]}**: '
        ptype = parameter['type']
        if 'rust-type' in parameter:
            ptype = parameter['rust-type']
        human_type = rust_type_to_human_str(ptype, entry_type)
        output += f'{human_type}'

        if 'default' in parameter:
            default = parameter['default']
            if default is not True:
                if default == '':
                    output += ' ``("")``'
                else:
                    output += f' ``({default})``'

        if 'description' in parameter:
            description = parameter['description']
            output += ' - ' + description

        if 'supported-values' in parameter:
            values = ', '.join(parameter['supported-values'])
            output += '. Supported values are: ' + values

        output += '\n'

    output += '\n'

    return output

def process_object(object_name, entries, entry_type, is_setting_struct=False, lua_equivalent=None):
    output = f'.. _yaml-{entry_type}-{object_name}:\n\n'

    output += f'{object_name}\n'
    output += '-' * len(object_name) + '\n'
    output += '\n'

    if 'description' in entries:
        description = entries['description']
        output += description + '\n'
        output += '\n'

    if lua_equivalent is not None:
        output += f'Lua equivalent: :func:`{lua_equivalent}`\n\n'

    if 'parameters' in entries:
        if not is_setting_struct:
            output += "Parameters:\n\n"
        parameters = entries['parameters']
        output += print_structure(parameters, entry_type)
        output += '\n'

    return output

def get_temporary_file_for_generated_content(directory):
    generated_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir=directory, delete=False)
    generated_fp.write('.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py\n\n')
    return generated_fp

def process_settings(def_file):
    output = '''.. raw:: latex

    \\setcounter{secnumdepth}{-1}

YAML configuration reference
============================

Since 2.0.0, :program:`dnsdist` supports the YAML configuration format in addition to the existing Lua one.

If the configuration file passed to :program:`dnsdist` via the ``-C`` command-line switch ends in ``.yml``, it is assumed to be in the new YAML format, and an attempt to load a Lua configuration file with the same name but the ``.lua`` will be done before loading the YAML configuration. If the names ends in ``.lua``, there will also be an attempt to find a file with the same name but ending in ``.yml``. Otherwise the existing Lua configuration format is assumed.

By default, when a YAML configuration file is used, any Lua configuration file used along the YAML configuration should only contain functions, and ideally even those should be defined either inline in the YAML file or in separate files included from the YAML configuration, for clarity. It is however possible to change this behaviour using the :func:`enableLuaConfiguration` directive to enable Lua configuration directives, but it is strongly advised not to use this directive unless absolutely necessary, and to prefer doing all the configuration in either Lua or YAML but to not mix them.
Note that Lua directives that can be used at runtime are always available via the :doc:`../guides/console`, regardless of whether they are enabled during configuration.

It is possible to access objects declared in the YAML configuration from the console via :func:`getObjectFromYAMLConfiguration`.

A YAML configuration file contains several sections, that are described below.

'''

    objects = get_objects(def_file)
    for object_name, entries in sorted(objects.items()):
        if object_name == 'GlobalConfiguration':
            output += process_object(object_name, entries, 'settings', True)
            break

    output += '\n'

    for object_name, entries in sorted(objects.items()):
        if object_name != 'GlobalConfiguration':
            output += process_object(object_name, entries, 'settings', True, entries['lua-name'] if 'lua-name' in entries else None)

    return output

def process_selectors_or_actions(def_file, entry_type):
    title = f'YAML {entry_type} reference'
    object_name = get_rust_object_name(entry_type)
    output = f'''.. raw:: latex

    \\setcounter{{secnumdepth}}{{-1}}

.. _yaml-settings-{object_name}:

{title}
'''
    output += len(title)*'=' + '\n\n'
    entries = get_definitions_from_file(def_file)

    suffix = object_name
    for entry in entries:
        object_name = get_rust_object_name(entry['name'])
        lua_equivalent = object_name + ('Rule' if entry_type == 'selector' else suffix)
        if 'no-lua-equivalent' in entry:
            lua_equivalent = None
        output += process_object(object_name + suffix, entry, 'settings', lua_equivalent=lua_equivalent)

    return output

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/source/dir>')
        sys.exit(1)

    source_dir = sys.argv[1]
    docs_folder = f'{source_dir}/docs/'
    if not os.path.isdir(docs_folder):
        print('Skipping settings documentation generation because the docs/ folder does not exist')
        return

    generated_fp = get_temporary_file_for_generated_content(docs_folder)
    output = process_settings(f'{source_dir}/dnsdist-settings-definitions.yml')
    generated_fp.write(output)
    os.rename(generated_fp.name, f'{docs_folder}/reference/yaml-settings.rst')

    generated_fp = get_temporary_file_for_generated_content(docs_folder)
    output = process_selectors_or_actions(f'{source_dir}/dnsdist-actions-definitions.yml', 'action')
    generated_fp.write(output)
    os.rename(generated_fp.name, f'{docs_folder}/reference/yaml-actions.rst')

    generated_fp = get_temporary_file_for_generated_content(docs_folder)
    output = process_selectors_or_actions(f'{source_dir}/dnsdist-response-actions-definitions.yml', 'response-action')
    generated_fp.write(output)
    os.rename(generated_fp.name, f'{docs_folder}/reference/yaml-response-actions.rst')

    generated_fp = get_temporary_file_for_generated_content(docs_folder)
    output = process_selectors_or_actions(f'{source_dir}/dnsdist-selectors-definitions.yml', 'selector')
    generated_fp.write(output)
    os.rename(generated_fp.name, f'{docs_folder}/reference/yaml-selectors.rst')

    Path('.yaml-settings.stamp').touch()

if __name__ == '__main__':
    main()
