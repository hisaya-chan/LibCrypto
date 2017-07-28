#ifndef MD5_H
#define MD5_H

#include <assert.h>
#include <stdlib.h>

/* WARNING :
 * This implementation is using 32 bits long values for sizes
 */
typedef unsigned int md5_size;

/* MD5 context */
struct md5_ctx {
	struct {
		unsigned int A, B, C, D; /* registers */
	} regs;
	unsigned char *buf;
	md5_size size;
	md5_size bits;
};

/* Size of the MD5 buffer */
#define MD5_BUFFER 1024

/* Basic md5 functions */
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))

/* Rotate left 32 bits values (words) */
#define ROTATE_LEFT(w,s) ((w << s) | ((w & 0xFFFFFFFF) >> (32 - s)))

#define FF(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + F(b,c,d) + x + t), s))
#define GG(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + G(b,c,d) + x + t), s))
#define HH(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + H(b,c,d) + x + t), s))
#define II(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + I(b,c,d) + x + t), s))

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21


#define memcopy(a,b,c) md5_memcopy ((a), (b), (c))
#define memst(a,b,c) md5_memset ((a), (b), (c))

#define GET_UINT32(a,b,i)				\
{							\
(a) = ( (unsigned int) (b)[(i)	]      )	\
| ( (unsigned int) (b)[(i)+1] << 8 )	\
| ( (unsigned int) (b)[(i)+2] << 16)	\
| ( (unsigned int) (b)[(i)+3] << 24);	\
}


//unsigned char *md5 (unsigned char *, md5_size, unsigned char *);
void md5_init (struct md5_ctx *);
void md5_update (struct md5_ctx *context);
void md5_final (unsigned char *digest, struct md5_ctx *context);

#endif /* MD5_H */
