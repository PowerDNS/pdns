#define fatal(...) do { fprintf(stderr, __VA_ARGS__); abort(); } while (0)
