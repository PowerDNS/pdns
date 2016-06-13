lua.hpp:
	$(AM_V_GEN)echo 'extern "C" {' > $@
	@echo '#include "lua.h"' >> $@
	@echo '#include "lualib.h"' >> $@
	@echo '#include "lauxlib.h"' >> $@
	@echo '}' >> $@
