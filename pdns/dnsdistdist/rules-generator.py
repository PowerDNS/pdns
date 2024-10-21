#!/usr/bin/python3
import sys
import yaml

def is_value_rust_default(rust_type, value):
    """Is a value the same as its corresponding Rust default?"""
    if rust_type == 'bool':
        return value == 'false'
    if rust_type  in ('u8', 'u32', 'u64'):
        return value in (0, '0', '')
    if rust_type == 'f64':
        return value in ('0.0', 0.0)
    if rust_type == 'String':
        return value == ''
    return False

def get_rust_field_name(name):
    return name.replace('-', '_').lower()

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

def get_rust_default_definition(rust_type, default, rename):
    if default is None:
        return ''
    rename_value = f'rename = "{rename}", ' if rename else ''
    if default is True or is_value_rust_default(rust_type, default):
        return f'#[serde({rename_value}default, skip_serializing_if = "crate::is_default")]'
    type_upper = rust_type.upper()
    return f'''#[serde({rename_value}default = "crate::{type_upper}::<{default}>::value", skip_serializing_if = "crate::{type_upper}::<{default}>::is_equal")]'''

def get_rust_struct_from_definition(name, keys):
    if not 'parameters' in keys:
        return ''
    obj_name = get_rust_object_name(name)
    name_field = ''
    if 'generate-name-field' in keys and keys['generate-name-field'] == True:
        name_field = '''         #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,\n'''
    str = f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct {obj_name}Configuration {{
{name_field}'''
    for parameter in keys['parameters']:
        parameter_name = get_rust_field_name(parameter['name']) if parameter['name'] != 'namespace' else 'name_space'
        rust_type = parameter['type']
        rename = parameter['name'] if parameter_name != parameter['name'] else None
        default_str = get_rust_default_definition(rust_type, parameter['default'] if 'default' in parameter else None, rename)
        if default_str:
            str += '        ' + default_str + '\n'
        str += f'        {parameter_name}: {rust_type},\n'
    str += '    }\n'
    return str

def get_definitions_from_file(def_file):
    with open(def_file, 'rt', encoding="utf-8") as fd:
        definitions = yaml.safe_load(fd.read())
        return definitions

def gather_sections(definitions):
    sections = {}
    for key in definitions:
        entry = definitions[key]
        if 'section' in entry:
            section_name = entry['section']
            sections[section_name] = entry['type'] if 'type' in entry else None
    return sections

def get_rust_obj_for_section(section_name, def_name, def_keys):
    if 'type' in def_keys and def_keys['type'] == 'list':
        name = get_rust_object_name(def_name)
        return f'Vec<{name}Configuration>'
    name = get_rust_object_name(def_name)
    return f'{name}Configuration'

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/definitions/file>')
        sys.exit(1)

    definitions = get_definitions_from_file(sys.argv[1])
    sections = gather_sections(definitions)
    global_objects = {}

    for definition_name, keys in definitions.items():
        if 'section' in keys and keys['section'] != 'none':
                continue

        print(get_rust_struct_from_definition(definition_name, keys))

    for section, section_type in sections.items():

        for definition_name, keys in definitions.items():
            if not 'section' in keys:
                continue
            if keys['section'] == section:
                if section == 'global':
                    if 'type' in keys and keys['type'] != 'list':
                        global_objects[definition_name] = keys['type']
                    else:
                        global_objects[definition_name] = get_rust_obj_for_section(section, definition_name, keys)
                print(get_rust_struct_from_definition(definition_name, keys))


        if section != 'global':
            if section_type is not None and section_type != 'list':
                global_objects[section] = section_type
                continue

            global_objects[section] = get_rust_object_name(section) + 'Configuration'

            print(f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct {section.capitalize()}Configuration {{''')
            for definition_name, keys in definitions.items():
                if 'section' in keys and keys['section'] == section:
                    field_name = get_rust_field_name(definition_name)
                    name = get_rust_object_name(definition_name)
                    obj_type = f'{name}Configuration' if not 'type' in keys or keys['type'] != 'list' else f'Vec<{name}Configuration>'
                    print(f'        {field_name}: {obj_type},')

            print('    }\n')

    # the cxx-compatible Global configuration object
    print('''    #[derive(Default)]
    struct GlobalConfiguration {''')
    for obj, name in global_objects.items():
        field_name = get_rust_field_name(obj)
        if field_name == 'selectors':
            name = 'Vec<SharedDNSSelector>'
            print(f'        {field_name}: {name},')
        else:
            print(f'        {field_name}: {name},')

    print('    }\n')

    # then the Serde one
    print('''#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct GlobalConfigurationSerde {''')
    for obj, name in global_objects.items():
        field_name = get_rust_field_name(obj)
        rename = obj if field_name != obj else None
        default_str = get_rust_default_definition(name, True, rename)
        if default_str:
            print('    ' + default_str)
        print(f'    {field_name}: {name},')

    print('}\n')


if __name__ == '__main__':
    main()
