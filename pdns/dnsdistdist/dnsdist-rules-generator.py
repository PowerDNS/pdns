#!/usr/bin/python3
"""Load action and selector definitions and generates C++ factory and Lua bindings code."""
# 1/ Loads the action definitions from:
# - dnsdist-actions-definitions.yml
# - dnsdist-response-actions-definitions.yml
# and generates C++ factory to create the objects
# for these actions from the corresponding parameters:
# - dnsdist-actions-factory-generated.cc
# - dnsdist-actions-factory-generated.hh
# - dnsdist-response-actions-factory-generated.cc
# - dnsdist-response-actions-factory-generated.hh
# as well as Lua bindings for them:
# - dnsdist-lua-actions-generated.cc
# - dnsdist-lua-response-actions-generated.cc
# 2/ Loads the selector definitions from:
# - dnsdist-selectors-definitions.yml
# and generates C++ factory to create the objects
# for these selectors from the corresponding parameters:
# - dnsdist-selectors-factory-generated.cc
# - dnsdist-selectors-factory-generated.hh
# as well as the Lua bindings for them:
# - dnsdist-lua-selectors-generated.cc
# The format of the definitions, in YAML, is a simple list of items.
# Each item has a name and an optional list of parameters.
# Parameters have a name, a type, and optionally a default value
# Types are the Rust ones, converted to the C++ equivalent when needed
# Default values are written as quoted strings, with the exception of the
# special unquoted true value which means to use the default value for the
# object type, which needs to exist.
# Items can optionally have the following properties:
# - 'skip-lua' means that the corresponding Lua bindings will not be generated, which is useful for objects taking parameters that cannot be directly mapped
# - 'skip-cpp' means that the corresponding C++ factory and Lua bindings will not be generated, which is useful for objects taking parameters that cannot be directly mapped
# - 'skip-rust' is not used by this script but is used by the dnsdist-settings-generator.py one, where it means that the C++ code to create the Rust-side version of an action or selector will not generated
# - 'skip-serde' is not used by this script but is used by the dnsdist-settings-generator.py one, where it means that the Rust structure representing that action or selector in the YAML setting will not be directly created by Serde. It is used for selectors that reference another selector themselves, or actions referencing another action.
import os
import tempfile
import yaml

def get_definitions_from_file(def_file):
    with open(def_file, 'rt', encoding="utf-8") as fd:
        definitions = yaml.safe_load(fd.read())
        return definitions

def is_vector_of(type_str):
    return type_str.startswith('Vec<')

def type_to_cpp(type_str, lua_interface, inside_container=False):
    if is_vector_of(type_str):
        sub_type = type_str[4:-1]
        return 'std::vector<' + type_to_cpp(sub_type, lua_interface, True) + '>'

    if type_str == 'u8':
        return 'uint8_t'
    if type_str == 'u16':
        return 'uint16_t'
    if type_str == 'u32':
        return 'uint32_t'
    if type_str == 'u64':
        return 'uint64_t'
    if type_str == 'f64':
        return 'double'
    if type_str == 'String':
        if lua_interface:
            return 'std::string'
        if inside_container:
            return 'std::string'
        return 'const std::string&'
    return type_str

def get_cpp_object_name(name, is_class=True):
    object_name = ''
    capitalize = is_class
    for char in name:
        if char == '-':
            capitalize = True
            continue
        if capitalize:
            char = char.upper()
            capitalize = False
        object_name += char

    return object_name

def get_cpp_parameter_name(name):
    return get_cpp_object_name(name, is_class=False)

def get_cpp_parameters_definition(parameters, lua_interface):
    output = ''
    for parameter in parameters:
        pname = get_cpp_parameter_name(parameter['name'])
        ptype = type_to_cpp(parameter['type'], lua_interface)
        if 'default' in parameter:
            if lua_interface:
                ptype = type_to_cpp(parameter['type'], lua_interface, True)
                ptype = f'boost::optional<{ptype}>'
            elif not 'cpp-optional' in parameter or parameter['cpp-optional']:
                ptype = type_to_cpp(parameter['type'], lua_interface, True)
                ptype = f'std::optional<{ptype}>'
        if len(output) > 0:
            output += ', '
        output += f'{ptype} {pname}'
    return output

def get_cpp_parameters(parameters, lua_interface):
    output = ''
    for parameter in parameters:
        pname = get_cpp_parameter_name(parameter['name'])
        if len(output) > 0:
            output += ', '
        default = None
        if not 'default' in parameter:
            output += f'{pname}'
            continue

        cpp_optional = not 'cpp-optional' in parameter or parameter['cpp-optional']
        if lua_interface and not cpp_optional:
            # We are the Lua binding, and the factory does not handle optional values
            # -> pass the value if any, and the default otherwise
            default = parameter['default']
        elif lua_interface and cpp_optional:
            # we are the Lua binding, the factory does handle optional values,
            # -> boost::optional to std::optional
            output += f'boostToStandardOptional({pname})'
            continue
        elif not lua_interface and cpp_optional:
            # We are the C++ factory and we do handle optional values
            # -> pass the value if any, and the default otherwise
            default = parameter['default']
        else:
            # We are the C++ factory and we do not handle optional values
            # -> pass the value we received
            output += f'{pname}'
            continue

        if default == '':
            default = '""'
        if default == True:
            default = '{}'

        output += f'{pname} ? *{pname} : {default}'

    return output

def get_temporary_file_for_generated_code():
    generated_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir='.', delete=False)
    generated_fp.write('// !! This file has been generated by dnsdist-rules-generator.py, do not edit by hand!!\n')
    return generated_fp

def generate_actions_factory_header(definitions, response=False):
    suffix = 'ResponseAction' if response else 'Action'
    shared_object_type = f'DNS{suffix}'
    generated_fp = get_temporary_file_for_generated_code()

    for action in definitions:
        if 'skip-cpp' in action and action['skip-cpp']:
            continue
        name = get_cpp_object_name(action['name'])
        output = f'std::shared_ptr<{shared_object_type}> get{name}{suffix}('
        if 'parameters' in action:
            output += get_cpp_parameters_definition(action['parameters'], False)
        output += ');\n'
        generated_fp.write(output)

    output_file_name = 'dnsdist-response-actions-factory-generated.hh' if response else 'dnsdist-actions-factory-generated.hh'
    os.rename(generated_fp.name, output_file_name)

def generate_actions_factory(definitions, response=False):
    suffix = 'ResponseAction' if response else 'Action'
    generated_fp = get_temporary_file_for_generated_code()

    for action in definitions:
        if 'skip-cpp' in action and action['skip-cpp']:
            continue
        name = get_cpp_object_name(action['name'])
        output = f'std::shared_ptr<DNS{suffix}> get{name}{suffix}('
        if 'parameters' in action:
            output += get_cpp_parameters_definition(action['parameters'], False)
        output += ')\n{\n'
        output += f'  return std::shared_ptr<DNS{suffix}>(new {name}{suffix}('
        if 'parameters' in action:
            output += get_cpp_parameters(action['parameters'], False)
        output += '));\n'
        output += '}\n'
        generated_fp.write(output)

    output_file_name = 'dnsdist-response-actions-factory-generated.cc' if response else 'dnsdist-actions-factory-generated.cc'
    os.rename(generated_fp.name, output_file_name)

def generate_lua_actions_bindings(definitions, response=False):
    suffix = 'ResponseAction' if response else 'Action'
    generated_fp = get_temporary_file_for_generated_code()

    for action in definitions:
        if 'skip-cpp' in action and action['skip-cpp']:
            continue
        if 'skip-lua' in action and action['skip-lua']:
            continue
        name = get_cpp_object_name(action['name'])
        output = f'luaCtx.writeFunction("{name}{suffix}", []('
        if 'parameters' in action:
            output += get_cpp_parameters_definition(action['parameters'], True)
        output += ') {\n'
        output += f'  return dnsdist::actions::get{name}{suffix}('
        if 'parameters' in action:
            output += get_cpp_parameters(action['parameters'], True)
        output += ');\n'
        output += '});\n'
        generated_fp.write(output)

    output_file_name = 'dnsdist-lua-response-actions-generated.cc' if response else 'dnsdist-lua-actions-generated.cc'
    os.rename(generated_fp.name, output_file_name)

def generate_selectors_factory_header(definitions):
    generated_fp = get_temporary_file_for_generated_code()

    for selector in definitions:
        if 'skip-cpp' in selector and selector['skip-cpp']:
            continue
        name = get_cpp_object_name(selector['name'])
        output = f'std::shared_ptr<{name}Rule> get{name}Selector('
        if 'parameters' in selector:
            output += get_cpp_parameters_definition(selector['parameters'], False)
        output += ');\n'
        generated_fp.write(output)

    output_file_name = 'dnsdist-selectors-factory-generated.hh'
    os.rename(generated_fp.name, output_file_name)

def generate_selectors_factory(definitions, response=False):
    generated_fp = get_temporary_file_for_generated_code()

    for selector in definitions:
        if 'skip-cpp' in selector and selector['skip-cpp']:
            continue
        name = get_cpp_object_name(selector['name'])
        output = f'std::shared_ptr<{name}Rule> get{name}Selector('
        if 'parameters' in selector:
            output += get_cpp_parameters_definition(selector['parameters'], False)
        output += ')\n{\n'
        output += f'  return std::make_shared<{name}Rule>('
        if 'parameters' in selector:
            output += get_cpp_parameters(selector['parameters'], False)
        output += ');\n'
        output += '}\n'
        generated_fp.write(output)

    output_file_name = 'dnsdist-selectors-factory-generated.cc'
    os.rename(generated_fp.name, output_file_name)

def generate_lua_selectors_bindings(definitions):
    generated_fp = get_temporary_file_for_generated_code()

    for selector in definitions:
        if 'skip-cpp' in selector and selector['skip-cpp']:
            continue
        if 'skip-lua' in selector and selector['skip-lua']:
            continue
        name = get_cpp_object_name(selector['name'])
        output = f'luaCtx.writeFunction("{name}Rule", []('
        if 'parameters' in selector:
            output += get_cpp_parameters_definition(selector['parameters'], True)
        output += ') {\n'
        output += f'  return std::shared_ptr<DNSRule>(dnsdist::selectors::get{name}Selector('
        if 'parameters' in selector:
            output += get_cpp_parameters(selector['parameters'], True)
        output += '));\n'
        output += '});\n'
        generated_fp.write(output)

    output_file_name = 'dnsdist-lua-selectors-generated.cc'
    os.rename(generated_fp.name, output_file_name)

def main():
    definitions = get_definitions_from_file('dnsdist-actions-definitions.yml')
    generate_actions_factory_header(definitions)
    generate_actions_factory(definitions)
    generate_lua_actions_bindings(definitions)

    definitions = get_definitions_from_file('dnsdist-response-actions-definitions.yml')
    generate_actions_factory_header(definitions, response=True)
    generate_actions_factory(definitions, response=True)
    generate_lua_actions_bindings(definitions, response=True)

    definitions = get_definitions_from_file('dnsdist-selectors-definitions.yml')
    generate_selectors_factory_header(definitions)
    generate_selectors_factory(definitions)
    generate_lua_selectors_bindings(definitions)

if __name__ == '__main__':
    main()
