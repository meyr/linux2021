#include <stdint.h>
#include <stdio.h>
  
#define __DECLARE_ROTATE(bits, type)                   \
    static inline type rotl##bits(const type v, int c) \
    {                                                  \
        const int mask = (bits) - (1);                 \
        c &= mask;                                     \
                                                       \
        return (v << c) | (v >> ((-c) & mask));        \
    }                                                  \
                                                       \
    static inline type rotr##bits(const type v, int c) \
    {                                                  \
        const int mask = (bits) - (1);                 \
        c &= mask;                                     \
                                                       \
        return (v >> c) | (v << ((-c) & mask));        \
    }

#define DECLARE_ROTATE(bits) __DECLARE_ROTATE(bits, uint##bits##_t)

DECLARE_ROTATE(64);
DECLARE_ROTATE(32);
DECLARE_ROTATE(16);
DECLARE_ROTATE(8);

static inline void dump_8bits(uint8_t _data)
{   
	int i;
    for (i = 0; i < 8; ++i) {
        printf("%d", (_data & (0x80 >> i)) ? 1 : 0);
	}
	printf("\n");
}


int main(int argc, const char *argv[])
{
	unsigned char data = 0x17;
	dump_8bits(data);
	dump_8bits(rotl8(data, 1));
	dump_8bits(rotl8(data, 2));
	dump_8bits(rotl8(data, 3));
	dump_8bits(rotl8(data, 4));
	dump_8bits(rotl8(data, 5));
	dump_8bits(rotl8(data, 6));
	dump_8bits(rotl8(data, 7));
	dump_8bits(rotl8(data, 8));

	printf("\n");

	dump_8bits(data);
	dump_8bits(rotr8(data, 1));
	dump_8bits(rotr8(data, 2));
	dump_8bits(rotr8(data, 3));
	dump_8bits(rotr8(data, 4));
	dump_8bits(rotr8(data, 5));
	dump_8bits(rotr8(data, 6));
	dump_8bits(rotr8(data, 7));
	dump_8bits(rotr8(data, 8));

	return 0;
}
