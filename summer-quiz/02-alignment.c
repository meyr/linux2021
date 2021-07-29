#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

static inline uintptr_t align_up(uintptr_t sz, size_t alignment)
{
    uintptr_t mask = alignment - 1;
    if ((alignment & mask) == 0) {  /* if the aligment is power of 2 */
        return (sz + mask) & ~mask;       
    }
    return (((sz + mask) / alignment) * alignment);
}

void test(uintptr_t value, uintptr_t expect)
{
	printf("0x%lx, 0x%lx\n", value, expect);
	printf("%s\n", value == expect ? "pass" : "fail");
}

int main(int argc, const char *argv[])
{
	test(align_up(120, 4), 120);
	test(align_up(121, 4), 124);
	test(align_up(122, 4), 124);
	test(align_up(123, 4), 124);
	return 0;
}
