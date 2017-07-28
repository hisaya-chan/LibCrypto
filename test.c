#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "encrypt.h"

/**
 *  *
 *   * Usage : xor_crypt key input_file output_file
 *    *
 *     */
int main(int argc, char *argv[]){
	FILE* pFile;
	long lsize;
	char* texte;
	char* chiffre;
	char* dechiffre;
	int size;
    int mode_debug=0;

    if((argc==3 && !strcmp(argv[2],"debug")) || (argc==5 && !strcmp(argv[4],"debug"))){
        mode_debug=1;}

	pFile = fopen( argv[1] , "rb");
	if (pFile == NULL) return 1;

	fseek (pFile, 0 , SEEK_END);  // Obtient la taille du fichier
	lsize = ftell (pFile);
	rewind (pFile);

	texte = (char*) malloc (lsize+1);   //Alloue mémoire pour le tampon, de la taille du fichier
	if (texte ==  NULL) return 2;

	fread (texte, 1, lsize, pFile); // copie fichier vers tampon
	texte[lsize]='\0';

	size = (strlen(texte)+7)/8;

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   XOR --------------\n");
	xor_crypt("une cle", texte,chiffre);
	xor_decrypt("une cle", chiffre, dechiffre);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

    chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
    dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
    printf("----------------   XOR avec taille du texte a dechiffrer --------------\n");
    xor_crypt("une cle", texte,chiffre);
    XOR_modif("une cle", chiffre, dechiffre,strlen(texte));
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
    printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   CESAR --------------\n");
	cesar_crypt(2, texte,chiffre);
	cesar_decrypt(2, chiffre, dechiffre);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   VIGENERE --------------\n");
	viginere_crypt("abc", texte,chiffre);
	viginere_decrypt("abc", chiffre, dechiffre);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

    chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   DES --------------\n");
	des_crypt("chabada", texte,chiffre,size);
	des_decrypt("chabada", chiffre, dechiffre, size);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   DES CBC --------------\n");
	des_crypt_cbc(texte, "chabada", texte, chiffre,size);
	des_decrypt_cbc(texte, "chabada", chiffre, dechiffre, size);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");


	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   3DES --------------\n");
	tripledes_crypt("chabada", "chibidi", texte,chiffre, size);
	tripledes_decrypt("chabada", "chibidi", chiffre, dechiffre, size);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
    printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   3DES CBC--------------\n");
	tripledes_crypt_cbc(texte, "chabada", "chibidi", texte,chiffre, size);
	tripledes_decrypt_cbc(texte, "chabada", "chibidi", chiffre, dechiffre, size);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");


	chiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
		dechiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
		printf("----------------   MD5 --------------\n");
	md5(texte, dechiffre);
	printf("'%s'\n",dechiffre);

	chiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
	printf("----------------   RSA --------------\n");
	rsa_crypt(7, 5141, texte, chiffre, strlen(texte));
	printf("test\n");
	rsa_decrypt(4279, 5141,  chiffre, dechiffre);
    if(mode_debug){
        printf("'%s'\n",chiffre);
        printf("'%s'\n",dechiffre);
    }
    printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");
	


    if (argc>=4) {
	    chiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
	    dechiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
	    printf("----------------   RSA avec generateur de cle --------------\n");
	    RsaPubKey * kpu=malloc(sizeof(RsaPubKey));
	    RsaPriKey * kpb=malloc(sizeof(RsaPriKey));
	    Huge valeurp = atoi(argv[2]);
	    Huge valeurq = atoi(argv[3]);
	    generator_rsakey(kpu, kpb , valeurp, valeurq);
	    rsa_crypt(kpu->e, kpu->n, texte, chiffre, strlen(texte));
	    rsa_decrypt(kpb->d, kpu->n,  chiffre, dechiffre);
	    if(mode_debug){
	        printf("cle publique : %lu, %lu\n",kpu->e,kpu->n);
	        printf("cle privee : %lu, %lu\n",kpb->d,kpb->n);
	        printf("'%s'\n",chiffre);
	        printf("'%s'\n",dechiffre);
	    }
	    printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");
	}

	fclose (pFile);  // ferme le flux et
	free(texte); // libère espace tampon

	return 0;
}
