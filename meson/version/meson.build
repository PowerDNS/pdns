# Generate version define
# Inputs: conf

# TODO Find a way to fix these ../.. because meson.current_source_dir() returns
# $GIT_ROOT/meson/version. Meson 0.56 introduces meson.project_source_root().
gen_version_prog = find_program('gen-version', dirs: meson.current_source_dir() / '..' / '..' / 'builder-support', required: true)
gen_version_prog_res = run_command(gen_version_prog, check: true)
version = gen_version_prog_res.stdout().strip()
conf.set_quoted('VERSION', version, description: 'Version')
