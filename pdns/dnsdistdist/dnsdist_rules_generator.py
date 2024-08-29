#!/usr/bin/env python3
"""Generate the constructor for DNSdist Selector (rules) and
Actions based on the definitions present in the YAML file.
"""

import yaml

def load_definitions(definitions_file):
    """Load the definitions from the supplied file"""
    with open(definitions_file, 'rt', encoding='utf-8') as fd:
        definitions = yaml.safe_load(fd.read())
        return definitions

def main():
    """Generate the constructors"""
    definitions_defs = 'dnsdist-rules-definitions.yml'
    definitions = load_definitions(definitions_defs)
    for rule in definitions:
        for rule_name, parameters in rule.items():
            print(f'{rule_name}::{rule_name}(std::vector<RuleParameter>& parameters):')
            for parameter in parameters:
                name = parameter['name']
                field_name = parameter['alias'] if 'alias' in parameter else name
                ptype = parameter['type']
                if 'default' in parameter:
                    default_value = parameter['default']
                    if isinstance(default_value, str) and not 'default-is-field' in parameter:
                        default_value = '"' + default_value + '"'
                    print(f'  d_{field_name}(getOptionalRuleParameter<{ptype}>("{rule_name}", parameters, "{name}", {default_value})')
                else:
                    print(f'  d_{field_name}(getRequiredRuleParameter<{ptype}>("{rule_name}", parameters, "{name}")')

            print('{')
            print('}')

if __name__ == '__main__':
    main()
