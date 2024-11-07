#!/usr/bin/python3

import os
import sys
import tempfile
import yaml

def quote(arg):
    """Return a quoted string"""
    return '"' + arg + '"'

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
    if rust_type == 'Vec<String>':
        # FIXME
        return True
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

def gen_rust_vec_default_functions(name, typeName, defvalue):
    """Generate Rust code for the default handling of a vector for typeName"""
    ret = f'// DEFAULT HANDLING for {name}\n'
    ret += f'fn default_value_{name}() -> Vec<dnsdistsettings::{typeName}> {{\n'
    ret += f'    let msg = "default value defined for `{name}\' should be valid YAML";'
    ret += f'    let deserialized: Vec<dnsdistsettings::{typeName}> = serde_yaml::from_str({quote(defvalue)}).expect(&msg);\n'
    ret += f'    deserialized\n'
    ret += '}\n'
    ret += f'fn default_value_equal_{name}(value: &Vec<dnsdistsettings::{typeName}>)'
    ret += '-> bool {\n'
    ret += f'    let def = default_value_{name}();\n'
    ret += '    &def == value\n'
    ret += '}\n\n'
    return ret

# Example snippet generated
# fn default_value_general_query_local_address() -> Vec<String> {
#    vec![String::from("0.0.0.0"), ]
#}
#fn default_value_equal_general_query_local_address(value: &Vec<String>) -> bool {
#    let def = default_value_general_query_local_address();
#    &def == value
#}
def gen_rust_stringvec_default_functions(default, name):
    """Generate Rust code for the default handling of a vector for Strings"""
    ret = f'// DEFAULT HANDLING for {name}\n'
    ret += f'fn default_value_{name}() -> Vec<String> {{\n'
    parts = re.split('[ \t,]+', default)
    if len(parts) > 0:
        ret += '    vec![\n'
        for part in parts:
            if part == '':
                continue
            ret += f'        String::from({quote(part)}),\n'
        ret += '    ]\n'
    else:
        ret  += '    vec![]\n'
    ret += '}\n'
    ret += f'fn default_value_equal_{name}(value: &Vec<String>) -> bool {{\n'
    ret += f'    let def = default_value_{name}();\n'
    ret += '    &def == value\n'
    ret += '}\n\n'
    return ret

def gen_rust_default_functions(rust_type, default, name):
    """Generate Rust code for the default handling"""
    if rust_type in ['Vec<String>']:
        return gen_rust_stringvec_default_functions(default, name)
    ret = f'// DEFAULT HANDLING for {name}\n'
    ret += f'fn default_value_{name}() -> {rust_type} {{\n'
    rustdef = quote(default)
    ret += f"    String::from({rustdef})\n"
    ret += '}\n'
    if rust_type == 'String':
        rust_type = 'str'
    ret += f'fn default_value_equal_{name}(value: &{rust_type})'
    ret += '-> bool {\n'
    ret += f'    value == default_value_{name}()\n'
    ret += '}\n\n'
    return ret

def get_rust_serde_annotations(rust_type, default, rename, obj, field, default_functions):
    rename_value = f'rename = "{rename}", ' if rename else ''
    if default is None:
        if not rename_value:
            return ''
        return f'#[serde({rename_value})]'
    if default is True or is_value_rust_default(rust_type, default):
        return f'#[serde({rename_value}default, skip_serializing_if = "crate::is_default")]'
    type_upper = rust_type.capitalize()
    if rust_type == 'bool':
        return f'''#[serde({rename_value}default = "crate::{type_upper}::<{default}>::value", skip_serializing_if = "crate::if_true")]'''
    if rust_type == 'String' or rust_type == 'Vec<String>':
        basename = obj + '_' + field
        default_functions.append(gen_rust_default_functions(rust_type, default, basename))
        return f'''#[serde({rename_value}default = "crate::default_value_{basename}", skip_serializing_if = "crate::default_value_equal_{basename}")]'''
    return f'''#[serde({rename_value}default = "crate::{type_upper}::<{default}>::value", skip_serializing_if = "crate::{type_upper}::<{default}>::is_equal")]'''

def get_rust_struct_from_definition(name, keys, default_functions):
    if not 'parameters' in keys:
        return ''
    obj_name = get_rust_object_name(name)
    name_field = ''
    if 'generate-name-field' in keys and keys['generate-name-field'] is True:
        name_field = '''         #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,\n'''
    output = f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct {obj_name}Configuration {{
{name_field}'''
    for parameter in keys['parameters']:
        parameter_name = get_rust_field_name(parameter['name']) if parameter['name'] != 'namespace' else 'name_space'
        rust_type = parameter['type']
        rename = parameter['name'] if parameter_name != parameter['name'] else None
        default_str = get_rust_serde_annotations(rust_type, parameter['default'] if 'default' in parameter else None, rename, get_rust_field_name(name), parameter_name, default_functions)
        if default_str:
            output += '        ' + default_str + '\n'
        output += f'        {parameter_name}: {rust_type},\n'
    output += '    }\n'
    return output

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

def get_rust_obj_for_section(def_name, def_keys):
    if 'type' in def_keys and def_keys['type'] == 'list':
        name = get_rust_object_name(def_name)
        return (f'Vec<{name}Configuration>', f'Vec<dnsdistsettings::{name}Configuration>')
    name = get_rust_object_name(def_name)
    return (f'{name}Configuration', f'dnsdistsettings::{name}Configuration')

def include_file(out_fp, include_file_name):
    with open(include_file_name, mode='r', encoding='utf-8') as in_fp:
        out_fp.write(f'// START INCLUDE {include_file_name}\n')
        out_fp.write(in_fp.read())
        out_fp.write(f'// END INCLUDE {include_file_name}\n')

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/definitions/file>')
        sys.exit(1)

    src_dir = './'
    definitions = get_definitions_from_file(sys.argv[1])
    default_functions = []
    sections = gather_sections(definitions)
    global_objects = {}
    generated_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir=src_dir + '/rust/src/')
    include_file(generated_fp, src_dir + 'rust-pre-in.rs')

    for definition_name, keys in definitions.items():
        if 'section' in keys and keys['section'] != 'none':
            continue

        generated_fp.write(get_rust_struct_from_definition(definition_name, keys, default_functions) + '\n')

    for section, section_type in sections.items():

        for definition_name, keys in definitions.items():
            if not 'section' in keys:
                continue
            if keys['section'] == section:
                if section == 'global':
                    if 'type' in keys and keys['type'] != 'list':
                        global_objects[definition_name] = (keys['type'], keys['type'])
                    else:
                        global_objects[definition_name] = get_rust_obj_for_section(definition_name, keys)
                generated_fp.write(get_rust_struct_from_definition(definition_name, keys, default_functions) + '\n')


        if section != 'global':
            if section_type is not None and section_type != 'list':
                global_objects[section] = (section_type, section_type)
                continue

            global_objects[section] = (get_rust_object_name(section) + 'Configuration', 'dnsdistsettings::' + get_rust_object_name(section) + 'Configuration')

            generated_fp.write(f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct {section.capitalize()}Configuration {{\n''')
            for definition_name, keys in definitions.items():
                if 'section' in keys and keys['section'] == section:
                    field_name = get_rust_field_name(definition_name)
                    name = get_rust_object_name(definition_name)
                    obj_type = f'{name}Configuration' if not 'type' in keys or keys['type'] != 'list' else f'Vec<{name}Configuration>'
                    generated_fp.write('        #[serde(default, skip_serializing_if = "crate::is_default")]\n')
                    generated_fp.write(f'        {field_name}: {obj_type},\n')

            generated_fp.write('    }\n')

    # the cxx-compatible Global configuration object
    generated_fp.write('''    #[derive(Default)]
    struct GlobalConfiguration {\n''')
    for obj, names in global_objects.items():
        field_name = get_rust_field_name(obj)
        if field_name == 'selectors':
            name = 'Vec<SharedDNSSelector>'
        else:
            name = names[0]
        generated_fp.write(f'        {field_name}: {name},\n')

    generated_fp.write('    }\n')

    include_file(generated_fp, src_dir + 'rust-middle-in.rs')

    # then the Serde one
    generated_fp.write('''#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct GlobalConfigurationSerde {\n''')
    for obj, names in global_objects.items():
        field_name = get_rust_field_name(obj)
        rename = obj if field_name != obj else None
        default_str = get_rust_serde_annotations(name[0], True, rename, field_name, 'global', default_functions)
        if default_str:
            generated_fp.write('    ' + default_str + '\n')
        if field_name == 'selectors':
            name = 'Vec<Selector>'
        else:
            name = names[1]
        generated_fp.write(f'    {field_name}: {name},\n')

    generated_fp.write('}\n')

    # the generated functions for the default values
    for function_def in default_functions:
        generated_fp.write(function_def + '\n')

    include_file(generated_fp, src_dir + 'rust-post-in.rs')

    os.rename(generated_fp.name, src_dir + '/rust/src/lib.rs')

if __name__ == '__main__':
    main()
