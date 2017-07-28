#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "encrypt.h"
#include <math.h>
#include "md5.h"

/**
 ** chiffrement utilisant le ou exclusif
 **/
void xor_crypt(char * key, char * texte, char* chiffre)
{
    char *cp; int c;
    if((cp = key)){
        if (texte != NULL ) {
            while ((c=*(texte++)) != '\0') {
                if (*cp == '\0' ) cp = key;
                c ^= *(cp++);
                *(chiffre++)=c;
            }
        }
    }
}

/**
 ** dechiffrement utilisant le ou exclusif
 **/
void xor_decrypt(char * key, char * texte, char* chiffre)
{
    char *cp; int c;
    if((cp = key)){
        if (texte != NULL ) {
            while ((c=*(texte++)) != '\0') {
                if (*cp == '\0' ) cp = key;
                c ^= *(cp++);
                *(chiffre++)=c;
            }
        }
    }
}

void XOR_modif(char * key, char * texte, char* chiffre,int size)
{
    char *cp; int c,i;
    if((cp = key)){
        for (i = 0; i < size; i++)
        {
            c=*(texte++);
            if (*cp == '\0' ) cp = key;
                c ^= *(cp++);
                *(chiffre++)=c;

        }
    }
}

/**
 *  * chiffrement utilisant cesar
 *   */
void cesar_crypt(int decallage, char * texte, char* chiffre)
{
    int c,cp;
    if((cp = decallage)){
        if (texte != NULL ) {
            if (chiffre != NULL ) {
                while (( c = *(texte++)) != '\0') {
                    if (c>='A' && c<='Z'){
                        c += cp-'A';
                        c%=26;
                        c+='A';
                    }
                    if (c>='a' && c<='z'){
                        c += cp-'a';
                        c%=26;
                        c+='a';
                    }
                    *(chiffre++)=c;
                }
            }
        }
    }
}

/**
 ** dechiffrement utilisant  cesar
 **/
void cesar_decrypt(int decallage, char * texte, char* chiffre)
{
    int c,cp;
    if((cp = decallage)){
        if (texte != NULL ) {
            if (chiffre != NULL ) {
                while (( c = *(texte++)) != '\0') {
                    if (c>='A' && c<='Z'){
                        c -= cp+'A'-26;
                        c%=26;
                        c+='A';
                    }
                    if (c>='a' && c<='z'){
                        c-=cp-26+'a';
                        c%=26;
                        c+='a';
                    }
                    *(chiffre++)=c;
                }
            }
        }
    }
}

/**
 *  * chiffrement utilisant viginere
 *   */
void viginere_crypt(char * key, char * texte, char* chiffre)
{
    char *cp;
    int c;
    if((cp = key)){
        if (texte != NULL ) {
            if (chiffre != NULL ) {
                while (( c = *(texte++)) != '\0') {
                    if (*cp == '\0' ){ cp=key;}
                    if (*cp>='A' && *cp<='Z' && c>='A' && c<='Z'){
                        c += *(cp++)- (2 * 'A');
                        c %= 26;
                        c += 'A';
                    }
                    if (*cp>='a' && *cp<='z' && c>='a' && c<='z' ){
                        c += *(cp++)- (2 * 'a');
                        c %= 26;
                        c += 'a';
                    }
                    if (*cp>='A' && *cp<='Z' && c>='a' && c<='z' ){
                        c += *(cp++)-'a'-'A';
                        c %= 26;
                        c += 'a';
                    }
                    if (*cp>='a' && *cp<='z' && c>='A' && c<='Z' ){
                        c += *(cp++)-'A'-'a';
                        c %= 26;
                        c += 'A';
                    }
                    *(chiffre++)=c;
                }
            }
        }
    }
}

/**
 *  * dechiffrement utilisant viginere
 *   */
void viginere_decrypt(char * key, char * texte, char* chiffre)
{
    char *cp;
    int c;
    if((cp = key)){
        if (texte != NULL ) {
            if (chiffre != NULL ) {
                while (( c = *(texte++)) != '\0') {
                    if (*cp == '\0' ) cp=key;
                    if (*cp>='A' && *cp<='Z' && c>='A' && c<='Z'){
                        c-='A';
                        c=c - ((*cp++)-'A')+26;
                        c %= 26;
                        c += 'A';
                    }
                    if (*cp>='a' && *cp<='z' && c>='a' && c<='z' ){
                        c=c - ((*cp++))+26;
                        c %= 26;
                        c += 'a';

                    }
                    if (*cp>='A' && *cp<='Z' && c>='a' && c<='z' ){
                        c-='a';
                        c=c - ((*cp++)-'A')+26;
                        c %= 26;
                        c += 'a';
                    }
                    if (*cp>='a' && *cp<='z' && c>='A' && c<='Z' ){
                        c-='A';
                        c=c - ((*cp++)-'a')+26;
                        c %= 26;
                        c += 'A';
                    }
                    *(chiffre++)=c;
                }
            }
        }
    }
}

/**
 *  * chiffrement utilisant DES
 *   */
void des_crypt(char * key, char * texte, char* chiffre, int size)
{
    char* bloc_bourrage=calloc(8,sizeof(char));
    int i,j=0;
    for (i=0; i<(size-1); i++) {
        des_encipher((unsigned char*)(texte+8*i),(unsigned char*)(chiffre+8*i),(unsigned char*)key);
    }
    while (j<8 && (texte[(size-1)*8+j]!='\0')) {
        bloc_bourrage[j]=texte[(size-1)*8+j];
        j++;
    }
    des_encipher((unsigned char*)bloc_bourrage,(unsigned char*)(chiffre+8*(size-1)),(unsigned char*)key);
    free(bloc_bourrage);
}


/**
 *  * d�chiffrement utilisant des
 *   */
void des_decrypt(char * key, char * texte, char* chiffre, int size)
{
    int i;
    for (i=0; i<(size); i++) {
        des_decipher((unsigned char*)(texte+8*i),(unsigned char*)(chiffre+8*i),(unsigned char*)key);
    }
}

/*
 * chiffrement utilisant des CBC
 */
void des_crypt_cbc(char* vect_init, char* key, char* texte, char* chiffre, int size)
{
    char* bloc_bourrage=calloc(8,sizeof(char));
    char* bloc_chiffre = calloc(8,sizeof(char)); // bloc de 8 octets qui va etre utilise pour le xor
    char* bloc_texte = calloc(8,sizeof(char));
    int i=0,j=0;
    char *cp; int c;

    memcpy(bloc_chiffre,vect_init,8);

    for (i=0; i<(size-1); i++) {
        memcpy(bloc_texte,texte+8*i,8); // bloc de texte clair a chiffrer

        /* XOR entre le texte clair et le bloc_chiffre */
        if((cp = bloc_chiffre)){
            for (j=0;j<8;j++) {
                (c=bloc_texte[j]);
                if (*cp == '\0' ) cp = bloc_chiffre;
                c ^= *(cp++);
                bloc_texte[j]=c;
            }
        }

        /* chiffrement DES du bloc obtenu */
        des_encipher((unsigned char*)(bloc_texte),(unsigned char*)(bloc_chiffre),(unsigned char*)key);
        memcpy(chiffre+8*i,bloc_chiffre,8);
    }

    /* Creation du dernier bloc a chiffrer*/
    j=0;
    while (j<8 && (texte[(size-1)*8+j]!='\0')) {
        bloc_bourrage[j]=texte[(size-1)*8+j];
        j++;
    }
    memcpy(bloc_texte,bloc_bourrage,8);

    /* XOR entre ce dernier bloc et bloc_chiffre */
    if((cp = bloc_chiffre)){
        for (j=0;j<8;j++) {
            (c=bloc_texte[j]);
            if (*cp == '\0' ) cp = bloc_chiffre;
            c ^= *(cp++);
            bloc_texte[j]=c;
        }
    }

    /* chiffrement DES du dernier bloc */
    des_encipher((unsigned char*)bloc_texte,(unsigned char*)(chiffre+8*(size-1)),(unsigned char*)key);

    /* liberation de la memoire */
    free(bloc_bourrage);
    free(bloc_texte);
    free(bloc_chiffre);
}


/*
 * dechiffrement utilisant DES CBC
 */
void des_decrypt_cbc(char* vect_init, char* key, char* chiffre, char* clair, int size)
{
    char* bloc_chiffre = calloc(8,sizeof(char));
    int i,k;
    char *cp; int c;

    memcpy(bloc_chiffre,vect_init,8);

    /* dechiffrement DES du premier bloc */
    des_decipher((unsigned char*)(chiffre),(unsigned char*)(clair),(unsigned char*)key);

    /* XOR entre bloc_chiffre et le premier bloc dechiffre */
    if((cp = bloc_chiffre)){
        for (k=0;k<8;k++) {
            (c=clair[k]);
            if (*cp == '\0' ) cp = bloc_chiffre;
            c ^= *(cp++);
            clair[k]=c;
        }
    }

    /* dechiffrement des autres blocs */
    for (i=1; i<(size); i++) {
        memcpy(bloc_chiffre,chiffre+8*(i-1),8);
        des_decipher((unsigned char*)(chiffre+8*i),(unsigned char*)(clair+8*i),(unsigned char*)key);

        /* XOR entre bloc_chiffre le bloc i du message (clair+8*i) */
        if((cp = bloc_chiffre)){
            for (k=0;k<8;k++) {
                (c=clair[k+8*i]);
                if (*cp == '\0' ) cp = bloc_chiffre;
                c ^= *(cp++);
                clair[k+8*i]=c;
            }
        }
    }
    free(bloc_chiffre);
}

/**
 *  * chiffrement utilisant 3des
 *   */
void tripledes_crypt(char * key1, char * key2, char * texte, char* chiffre,int size)
{
    char* chiffre1=malloc(8*size);
    des_crypt(key1, texte, chiffre, size);
    des_decrypt(key2, chiffre, chiffre1, size);
    des_crypt(key1, chiffre1, chiffre, size);
    free(chiffre1);
}


/**
 *  * dechiffrement utilisant 3des
 *   */
void tripledes_decrypt(char* key1, char* key2, char* texte, char* chiffre, int size)
{
    char* chiffre1=malloc(8*size);
    des_decrypt(key1, texte, chiffre, size);
    des_crypt(key2, chiffre, chiffre1, size);
    des_decrypt(key1, chiffre1, chiffre, size);
    free(chiffre1);
}

/*
 * chiffrement utilisant 3des CBC
 */
void tripledes_crypt_cbc(char * vect_init, char* key1, char* key2, char* texte, char* chiffre, int size)
{
    char* chiffre1=malloc(8*size);
    des_crypt_cbc(vect_init,key1, texte, chiffre, size);
    des_decrypt_cbc(vect_init,key2, chiffre, chiffre1, size);
    des_crypt_cbc(vect_init,key1, chiffre1, chiffre, size);
    free(chiffre1);

}


/*
 * dechiffrement utilisant 3des CBC
 */
void tripledes_decrypt_cbc(char * vect_init, char* key1, char* key2, char* chiffre, char* clair, int size)
{
    char* chiffre1=malloc(8*size);
    des_decrypt_cbc(vect_init,key1, chiffre, clair, size);
    des_crypt_cbc(vect_init,key2, clair, chiffre1, size);
    des_decrypt_cbc(vect_init,key1, chiffre1, clair, size);
    free(chiffre1);

}

/*
 * Calcul du condense MD5 du texte
 */

/* local functions */
static void md5_memcopy (unsigned char *, unsigned char *, const unsigned int);
static void md5_addsize (unsigned char *, md5_size , md5_size);
static void md5_encode (unsigned char *, struct md5_ctx *);

static unsigned char MD5_PADDING [64] = { /* 512 Bits */
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* md5 */
void md5(char * texte, char * hash)
{
    unsigned int len=strlen(texte);
    unsigned int buflen = len;
    struct md5_ctx *context;
    unsigned char digest[16];
    context = malloc (sizeof (struct md5_ctx));
    context->buf = malloc (buflen);
    context->size = 0;
    context->bits = 0;

    /* Init registries */
    context->regs.A = 0x67452301;
    context->regs.B = 0xefcdab89;
    context->regs.C = 0x98badcfe;
    context->regs.D = 0x10325476;

    do {
        memcopy (context->buf + context->size,(unsigned char*) texte + context->bits, buflen - context->size);
        context->size += buflen - context->size;
        md5_update (context);
    } while (len - context->bits > 64);

    md5_final ((unsigned char*) digest, context);
    int i;
    for (i=0; i<16; i++){
        sprintf (hash+i*2,"%02x%c",(unsigned char) digest [i],'\0');
    }
    free (context->buf);
    free (context);

}


/* md5_size is bytes while the size at the end of the message is in bits ... */
static void md5_addsize (unsigned char *M, md5_size index, md5_size oldlen)
{
    assert (((index * 8) % 512) == 448); /* If padding is not done then exit */

    M[index++] = (unsigned char) ((oldlen << 3) & 0xFF);
    M[index++] = (unsigned char) ((oldlen >> 5) & 0xFF);
    M[index++] = (unsigned char) ((oldlen >> 13) & 0xFF);
    M[index++] = (unsigned char) ((oldlen >> 21) & 0xFF);
    /* Fill with 0 because md5_size is 32 bits long */
    M[index++] = 0; M[index++] = 0;
    M[index++] = 0; M[index++] = 0;
}

/*
 * Update a context by concatenating a new block
 */
void md5_update (struct md5_ctx *context)
{
    unsigned char buffer [64]; /* 512 bits */
    int i;

    for (i = 0; context->size - i > 63; i += 64) {
        memcopy (buffer, context->buf + i, 64);
        md5_encode (buffer, context);
        context->bits += 64;
    }
    memcopy (buffer, context->buf + i, context->size - i);
    memcopy (context->buf, buffer, context->size - i);
    context->size -= i;
}

void md5_final (unsigned char *digest, struct md5_ctx *context)
{
    unsigned char buffer [64]; /* 512 bits */
    int i;

    assert (context->size < 64);

    if (context->size + 1 > 56) { /* We have to create another block */
        memcopy (buffer, context->buf, context->size);
        memcopy (buffer + context->size, MD5_PADDING, 64 - context->size);
        md5_encode (buffer, context);
        context->bits += context->size;
        context->size = 0;
        /* Proceed final block */
        memset (buffer, '\0', 56);
        /*memcopy (buffer, MD5_PADDING + 1, 56);*/
        md5_addsize (buffer, 56, context->bits);
        md5_encode (buffer, context);
    } else {
        memcopy (buffer, context->buf, context->size);
        context->bits += context->size;

        memcopy (buffer + context->size, MD5_PADDING, 56 - context->size);
        md5_addsize (buffer, 56, context->bits);
        md5_encode (buffer, context);
    }
    /* update digest */
    for (i = 0; i < 4; i++)
        digest [i] = (unsigned char) ((context->regs.A >> (i*8)) & 0xFF);
    for (i = 4; i < 8; i++)
        digest [i] = (unsigned char) ((context->regs.B >> ((i-4)*8)) & 0xFF);
    for (i = 8; i < 12; i++)
        digest [i] = (unsigned char) ((context->regs.C >> ((i-8)*8)) & 0xFF);
    for (i = 12; i < 16; i++)
        digest [i] = (unsigned char) ((context->regs.D >> ((i-12)*8)) & 0xFF);


}

static void md5_encode (unsigned char *buffer, struct md5_ctx *context)
{
    unsigned int a = context->regs.A, b = context->regs.B, c = context->regs.C, d = context->regs.D;
    unsigned int x[16];

    GET_UINT32 (x[ 0],buffer, 0);
    GET_UINT32 (x[ 1],buffer, 4);
    GET_UINT32 (x[ 2],buffer, 8);
    GET_UINT32 (x[ 3],buffer,12);
    GET_UINT32 (x[ 4],buffer,16);
    GET_UINT32 (x[ 5],buffer,20);
    GET_UINT32 (x[ 6],buffer,24);
    GET_UINT32 (x[ 7],buffer,28);
    GET_UINT32 (x[ 8],buffer,32);
    GET_UINT32 (x[ 9],buffer,36);
    GET_UINT32 (x[10],buffer,40);
    GET_UINT32 (x[11],buffer,44);
    GET_UINT32 (x[12],buffer,48);
    GET_UINT32 (x[13],buffer,52);
    GET_UINT32 (x[14],buffer,56);
    GET_UINT32 (x[15],buffer,60);

    /* Round 1 */
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
    GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */

    GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

    context->regs.A += a;
    context->regs.B += b;
    context->regs.C += c;
    context->regs.D += d;
}

/* OBSOLETE */
static void md5_memcopy (unsigned char *dest, unsigned char *src, unsigned int count)
{
    unsigned int i;

    for (i = 0; i < count; i++) {
        dest [i] = src [i];
    }
}

/****************************************************************
 *                                                               *
 *  -------------------------- modexp -------------------------  *
 *                                                               *
 ****************************************************************/

static Huge modexp(Huge a, Huge b, Huge n) {

	Huge               y;

	/****************************************************************
	 *                                                               *
	 *  Calcule (pow(a, b) % n) avec la m�thode du carr� binaire     *
	 *  et de la multiplication.                                     *
	 *                                                               *
	 ****************************************************************/

	y = 1;

	while (b != 0) {

		/*************************************************************
		 *                                                            *
		 *  Pour chaque 1 de b, on accumule dans y.                   *
		 *                                                            *
		 *************************************************************/

		if (b & 1)
			y = (y * a) % n;

		/*************************************************************
		 *                                                            *
		 *  �l�vation de a au carr� pour chaque bit de b.             *
		 *                                                            *
		 *************************************************************/

		a = (a * a) % n;

		/*************************************************************
		 *                                                            *
		 *  On se pr�pare pour le prochain bit de b.                  *
		 *                                                            *
		 *************************************************************/

		b = b >> 1;

	}

	return y;

}


/**
 * Transforme une chaine d'entier en chaine de caractere
 */
void inttotext(char * texte, char* chiffre){
	*chiffre='\0';
	int tmp=0;
	while((*texte) != '\0'){
	    // caractere (0..255 correspond pour nous a 100..355)
		if(10*tmp+(*(texte)-'0') > 356){
		    // on deduit donc 100 pour obtenir le bon caractere
			sprintf(chiffre+strlen(chiffre),"%c%c",tmp-100, '\0');
			tmp=0;
		}
		tmp=10*tmp+(*(texte)-'0');
		texte++;
	}
}

/**
 * Transforme une chaine de caractere en chaine d'entier
 */
void texttoint(char * texte, char* chiffre, int size){
    *chiffre='\0';
    int tmp;
    int i;
    for(i=0;i<size;i++){
        // on ajoute 100 pour eviter le probleme de disparition du 0 devnt les entiers entre 1 et 99 (001 a 099)
        // ceci evite de decouper le texte en bloc de taille < n et de les normaliser ensuite
        tmp=(*(texte+i)+100);
        if(tmp>=100)
            sprintf(chiffre+strlen(chiffre),"%d%c",tmp,'\0');
    }
}

/**
 * Chiffrement RSA
 */

Huge rsa_crypt1(Huge e,Huge n, Huge M){
    Huge c;
    c=modexp(M,e,n);
    return c;
}

Huge rsa_decrypt1(Huge d,Huge n, Huge c){
    Huge M;
    M=modexp(c,d,n);
    return M;
}

void rsa_crypt(int e, int n, char * texte, char* chiffre, int size)
{
  int tmp;
	Huge buf=0;
	char* pt;
	char* btmp = (char *)malloc((3*strlen(texte)+1) * sizeof(char));

	texttoint(texte,btmp,size);
  pt = btmp;
	*chiffre='\0';

	while((*pt) != '\0'){
		tmp=pt[0]-'0';
		if(100*buf + tmp >= n){
		  // on utilise le $ comme separateur de bloc
			sprintf(chiffre+strlen(chiffre),"%ld$%c", rsa_crypt1(e,n,buf),'\0');
			buf=0;
		}
		buf=10*buf+tmp;
		pt++;
	}
	sprintf(chiffre+strlen(chiffre),"%ld$%c",rsa_crypt1(e,n,buf),'\0');
  free (btmp);
  }

/**
 * Dechiffrement RSA
 */
void rsa_decrypt(int d, int n, char * texte, char* chiffre)
{
	int tmp;
	char* pt=texte;
	char* tmpc= (char *)malloc(strlen(texte) * sizeof(char));
	Huge buf=0;

	*tmpc='\0';
	while((*pt) != '\0'){
		// on utilise le $ comme separateur de bloc
	    if((*pt) == '$'){
			sprintf(tmpc+strlen(tmpc),"%ld%c",rsa_decrypt1(d,n,buf),'\0');
			buf=0;
		}else{
			tmp=*pt-'0';
			buf=10*buf+tmp;
		}
		pt++;
	}
	sprintf(tmpc+strlen(tmpc),"%ld%c",rsa_decrypt1(d,n,buf),'\0');
	inttotext(tmpc,chiffre);
  free(tmpc);
}

/*
 * Generateur cle RSA
 */

Huge gcd ( Huge a, Huge b )
{
    Huge r;
    if (a!=0 && b!=0) {
        if (a<b) {
            a-=b;
            b+=a;
            a=b-a;
        }
        r=a%b;
        if (r==0) {
            return b;
        }
        else return gcd(b,r);
    }
    else return 0;
}

/*
 * Petit theoreme de fermat, qui fait un test de primalite
 */
int fermat(Huge n){
    Huge a,b;
    srand(time(NULL)); // initialisation de rand
    a = rand()%(n-2)+2; // Choisir un entier aleatoire a<n et a>1
    b=modexp(a,n-1,n); // b= a^(n-1) (mod n)
    if (b!=1) { // n n'est pas premier
        return 0;
    }
    return 1; // n est potentiellement premier
}

/*
 * Generateur de nombres premiers
 */
Huge nb_premier(Huge p)
{
    Huge i=3;
    if (p > 2) {
        if (p%2 == 0){
            return nb_premier(p-1);
        }
        else { // p non divisible par 2
            if (!fermat(p)){ // p n'est pas premier
                return nb_premier(p-2);
            }
            else { // p est potentiellement premier
                Huge r;
                while ((r=p%i) != 0 && i<sqrt(p)) {
                    i+=2;
                }
                if (r==0) { // p divisible par i
                    return nb_premier(p-2);
                }
                else { // i>sqrt(p)
                  printf("%i\n",p);
                    return p;
                }
            }
        }
    }
    else if (p == 2) {
        return p;
    }
    else { // p<2
        return 0;
    }
}

/* generateur de cle RSA avec p et q pas obligatoirement premier */
void generator_rsakey(RsaPubKey * kpu, RsaPriKey * kpb , Huge valeurp, Huge valeurq){
    Huge phi_n,p,q;
    p = nb_premier(valeurp);
    q = nb_premier(valeurq);
    kpu->n = p*q;
    kpb->n=kpu->n;
    kpu->e=2;
    kpb->d=2;
    phi_n=(p-1)*(q-1);

    while (kpu->e<phi_n && gcd(kpu->e,phi_n)!=1) {
        kpu->e++;
    }

    while (kpb->d<phi_n && ((kpu->e*kpb->d)%phi_n)!=1) {
        kpb->d++;
    }
}
