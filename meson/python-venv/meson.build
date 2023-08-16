python_have_venv = false

dep_python_prog = dependency('python3', version: '>= 3.6', required: false)
if not dep_python_prog.found()
  warning('Python3 dependency not found')
  summary('Python', dep_python_prog.found(), bool_yn: true, section: 'Python')
  subdir_done()
endif

summary('Python', dep_python_prog.found(), bool_yn: true, section: 'Python')
summary('Implementation', dep_python_prog.name(), section: 'Python')
summary('Version', dep_python_prog.version(), section: 'Python')

python_prog_name = 'python' + dep_python_prog.version()
python_prog = find_program(python_prog_name, required: false)
if not python_prog.found()
  warning(python_prog_name + ' program not found')
  subdir_done()
endif

python_prog_res = run_command(python_prog, '-c', '"import venv"', check: false)
if python_prog_res.returncode() != 0
  warning(python_prog_name + ' venv module not found')
  summary('Python venv', false, bool_yn: true, section: 'Python')
  subdir_done()
endif

python_have_venv = true
summary('Have venv', python_have_venv, bool_yn: true, section: 'Python')
