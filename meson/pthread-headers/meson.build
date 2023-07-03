# Check pthread headers
# Inputs: deps conf

dep_threads = dependency('threads')
have_pthread_h = cxx.check_header('pthread.h', dependencies: dep_threads, required: true)
have_pthread_np_h = cxx.check_header('pthread_np.h', dependencies: dep_threads, prefix: '#include <pthread.h>')

deps += dep_threads
conf.set10('HAVE_PTHREAD_NP_H', have_pthread_np_h, description: 'pthread_np.h is available')

summary('Threads', dep_threads.found(), bool_yn: true, section: 'System')
summary('pthread.h', have_pthread_h, bool_yn: true, section: 'System')
summary('pthread_np.h', have_pthread_np_h, section: 'System')
