import sys, json, yaml

with open(sys.argv[1], mode='r', encoding='utf-8') as f_in:
    with open(sys.argv[2], mode='w', encoding='utf-8') as f_out:
        json.dump(yaml.safe_load(f_in.read()), f_out, indent=2, separators=(',', ': '))
