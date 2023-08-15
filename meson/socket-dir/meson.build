# Socket Dir
# Inputs: conf
# Outputs: opt_socket_dir

opt_socket_dir = get_option('socket-dir')
conf.set_quoted('LOCALSTATEDIR', opt_socket_dir, description: 'Local state or socket directory')
