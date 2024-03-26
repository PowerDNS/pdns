gen_version_prog = find_program('gen-version', dirs: product_source_dir / 'builder-support', required: true)
gen_version_prog_res = run_command(gen_version_prog, check: true)
product_version = gen_version_prog_res.stdout().strip()
conf.set_quoted('VERSION', product_version, description: 'Version')
