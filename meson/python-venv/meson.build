# Python Venv
# Outputs: python_have_venv

python_have_venv = false

dep_python = dependency('python3', version: '>= 3.6', required: false)
if not dep_python.found()
  warning('Python3 dependency not found')
  subdir_done()
endif

summary('Python', dep_python.found(), bool_yn: true, section: 'Configuration')
summary('Python Version', dep_python.version(), section: 'Configuration')

python_prog = 'python' + dep_python.version()
python_prog = find_program(python_prog, required: false)
if not python_prog.found()
  warning('Python3 program not found')
  subdir_done()
endif

python_prog_res = run_command(python_prog, '-c', '"import venv"', check: false)
if python_prog_res.returncode() != 0
  warning('Python3 venv module not found')
  subdir_done()
endif

python_have_venv = true
summary('Python venv', python_have_venv, bool_yn: true, section: 'Configuration')
