# LibCrypto
a personal crypto library (RSA, DES, 3DES MD5)

------------------------------
Arguments en ligne de commande
------------------------------

Exemples:  	
./test fichier_a_chiffrer
	on sait uniquement si le test a réussi ou pas

./test fichier_a_chiffrer debug
	on voit sur la sortie standard le résultat du chiffrement et du déchiffrement
	et on sait si le test a réussi ou pas

./test fichier_a_chiffrer nombre1 nombre2
	on a aussi comme test supplémentaire la génération de clés RSA avec les nombres choisis en arguments

./test fichier_a_chiffrer nombre1 nombre2 debug
	on affiche le résultat du chiffrement et déchiffrement de chaque test mais aussi les valeurs des clés publique et privée pour le test RSA avec génération de clé


--------------------------------------------------------------------------
Spécificités pour chaque algorithme de chiffrement et déchiffrement
--------------------------------------------------------------------------

Pour XOR :
	il ne faut pas que l'un des caractères de la clé de chiffrement et le caractère du texte soient les mêmes par exemple lorsqu'on fait un XOR entre 'a' et 'a' le résultat est null donc on ne pourra pas le déchiffrer.

	- alternative pour que le XOR marche en toute circonstance :
	pour le déchiffrement mettre en paramètre supplémentaire  la taille du texte à déchiffrer
	(voir XOR_modif() )

Pour César :
	supporte les minuscules et les majuscules
	les autres caractères ne sont pas modifiés

Pour Vigenère :
	supporte les minuscules et les majuscules
	les autres caractères ne sont pas modifiés

Pour RSA :
	modification des fonctions inttotext() et texttoint() pour que la fonction RSA fonctionne avec les 256 caractères de la table ascii et non plus seulement avec les 26 lettres de l'alphabet en minuscules.

Pour le générateur de cle RSA :
	- Pour trouver les nombres premier p et q :
	utilisation du petit théorème de Fermat pour un premier test de primalité
	puis si il est supposé être premier, vérification naïve en vérifiant que ce nombre n'est pas divisible par chaque entier impair inférieur à sa racine carré.
	sinon refaire le test avec l'entier impair inférieur à ce nombre et recommencer jusqu'à trouver un nombre premier
