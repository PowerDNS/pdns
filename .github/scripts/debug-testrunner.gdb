# http://sourceware.org/gdb/wiki/FAQ: to disable the
# "---Type <return> to continue, or q <return> to quit---"
# in batch mode:
set width 0
set height 0
set verbose off

catch throw std::bad_alloc
commands 1
  bt full
  quit
end

# must specify cmdline arg for "run"
# when running in batch mode! (then they are ignored)
run -p --log_level=test_suite
