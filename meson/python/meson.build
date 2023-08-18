py = import('python')
python_prog = py.find_installation('python3', required: false)

summary('Python', python_prog.found(), bool_yn: true, section: 'Python')
summary('Path', python_prog.full_path(), section: 'Python')
summary('Version', python_prog.version(), section: 'Python')
