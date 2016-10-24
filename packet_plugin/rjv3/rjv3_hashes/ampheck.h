
/*
	Copyright (C) 2009  Gabriel A. Petursson

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef AMPHECK_H
#define AMPHECK_H
#include <stdint.h>

#define ROR(x, y) (((x) >> (y)) ^ ((x) << ((sizeof(x) * 8) - (y))))
#define ROL(x, y) ((x) << (y) ^ ((x) >> (32 - (y))))

#define UNPACK_32_BE(x, str) { \
	*((str))     = (uint8_t) ((x) >> 24); \
	*((str) + 1) = (uint8_t) ((x) >> 16); \
	*((str) + 2) = (uint8_t) ((x) >>  8); \
	*((str) + 3) = (uint8_t) (x); \
}

#define UNPACK_64_BE(x, str) { \
	*((str))     = (uint8_t) ((x) >> 56); \
	*((str) + 1) = (uint8_t) ((x) >> 48); \
	*((str) + 2) = (uint8_t) ((x) >> 40); \
	*((str) + 3) = (uint8_t) ((x) >> 32); \
	*((str) + 4) = (uint8_t) ((x) >> 24); \
	*((str) + 5) = (uint8_t) ((x) >> 16); \
	*((str) + 6) = (uint8_t) ((x) >>  8); \
	*((str) + 7) = (uint8_t) (x); \
}

#define PACK_32_BE(str, x) { \
	*(x) = ((uint32_t) *((str)    ) << 24) \
	     ^ ((uint32_t) *((str) + 1) << 16) \
	     ^ ((uint32_t) *((str) + 2) <<  8) \
	     ^ ((uint32_t) *((str) + 3)); \
}

#define PACK_64_BE(str, x) { \
	*(x) = ((uint64_t) *((str)    ) << 56) \
	     ^ ((uint64_t) *((str) + 1) << 48) \
	     ^ ((uint64_t) *((str) + 2) << 40) \
	     ^ ((uint64_t) *((str) + 3) << 32) \
	     ^ ((uint64_t) *((str) + 4) << 24) \
	     ^ ((uint64_t) *((str) + 5) << 16) \
	     ^ ((uint64_t) *((str) + 6) << 8) \
	     ^ ((uint64_t) *((str) + 7)); \
}

#define UNPACK_32_LE(x, str) { \
	*((str))     = (uint8_t) (x); \
	*((str) + 1) = (uint8_t) ((x) >>  8); \
	*((str) + 2) = (uint8_t) ((x) >> 16); \
	*((str) + 3) = (uint8_t) ((x) >> 24); \
}

#define UNPACK_64_LE(x, str) { \
	*((str))     = (uint8_t) (x); \
	*((str) + 1) = (uint8_t) ((x) >>  8); \
	*((str) + 2) = (uint8_t) ((x) >> 16); \
	*((str) + 3) = (uint8_t) ((x) >> 24); \
	*((str) + 4) = (uint8_t) ((x) >> 32); \
	*((str) + 5) = (uint8_t) ((x) >> 40); \
	*((str) + 6) = (uint8_t) ((x) >> 48); \
	*((str) + 7) = (uint8_t) ((x) >> 56); \
}

#define PACK_32_LE(str, x) { \
	*(x) = ((uint32_t) *((str)    )) \
	     ^ ((uint32_t) *((str) + 1) <<  8) \
	     ^ ((uint32_t) *((str) + 2) << 16) \
	     ^ ((uint32_t) *((str) + 3) << 24); \
}

#define PACK_64_LE(str, x) { \
	*(x) = ((uint64_t) *((str)    )) \
	     ^ ((uint64_t) *((str) + 1) <<  8) \
	     ^ ((uint64_t) *((str) + 2) << 16) \
	     ^ ((uint64_t) *((str) + 3) << 24) \
	     ^ ((uint64_t) *((str) + 4) << 32) \
	     ^ ((uint64_t) *((str) + 5) << 40) \
	     ^ ((uint64_t) *((str) + 6) << 48) \
	     ^ ((uint64_t) *((str) + 7) << 56); \
}
#endif
