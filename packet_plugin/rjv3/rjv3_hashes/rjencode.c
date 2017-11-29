#include "rjencode.h"

void rj_encode(uint8_t *buf, int len)
{
	if (len > 0)
	{
		for (int i = 0; i < len; ++i)
		{
			buf[i] = ~(((buf[i] & 0x10) >> 1) | ((buf[i] & 0x20) >> 3) | ((buf[i] & 0x40) >> 5) | ((uint32_t)buf[i] >> 7) | (buf[i] & 8) << 1 | (buf[i] & 4) << 3 | (buf[i] & 2) << 5 | ((buf[i] & 1) << 7));
		}
	}
}

void rj_decode(uint8_t *buf, int len)
{
	if (len > 0)
	{
		for (int i = 0; i < len; ++i)
		{
			buf[i] = ((~buf[i] & 0x10) >> 1) | ((~buf[i] & 0x20) >> 3) | ((~buf[i] & 0x40) >> 5) | ((uint8_t)~buf[i] >> 7) | 2 * (~buf[i] & 8) | 8 * (~buf[i] & 4) | ((~buf[i] & 1) << 7) | 32 * (~buf[i] & 2);
		}
	}
}
