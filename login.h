#ifndef _LOGIN_
#define _LOGIN_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "../Animacoes/Funcoes_Anin/term.h"
#include "../Listas/structs.h"

//-------------------FUNCIONALIDADES--------------------

char Registrar (User *usuario);
char Autenticar (User* usuario);
char ChecaLogin (User *usuario);
char VirarAdmin (User *usuario);
char CriarAdmin (User *usuario);

//-----------------------FUNÇÕES------------------------

char Registrar (User *usuario) {
	char cripto[50] = {0};
	int check = 1;
	FILE * fregistro = fopen("Dados/login.txt", "a");

	if (!fregistro) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	if (!usuario)
		return 1;
	if (ChecaLogin(usuario))
		return 2;
	strcpy(cripto, usuario->login);
	strcat(cripto, usuario->senha);
	Criptografar(cripto);

	strcpy(usuario->senha, cripto);
	usuario->admin = 0;

	if (!fseek(fregistro, 0, SEEK_END))
		check = ftell(fregistro);
	if (!check)
		usuario->admin = 1;

	fprintf(fregistro, "%s:%s:%c\n", usuario->login, usuario->senha, usuario->admin ? '1' : '0');
	fclose(fregistro);
	return 0;
}

char Autenticar (User* usuario) {
	char linha[80] = {0};
	char cmp[80] = {0};
	char senha[50] = {0};
	FILE * fleitura = fopen("Dados/login.txt", "r");

	if (fleitura == NULL) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	if (!usuario)
		exit(2);
	strcpy(cmp, usuario->login);
	strcat(cmp, ":");

	strcpy(senha, usuario->login);
	strcat(senha, usuario->senha);
	Criptografar(senha);

	strcat(cmp, senha);

	if (usuario->admin)
		strcat(cmp, ":1");
	else
		strcat(cmp, ":0");

	while (!feof(fleitura)) {
		memset(linha, 0, 80);
		fgets(linha, 80, fleitura);

		for (size_t i = 0; i<80; i++) {
			if(linha[i] != '\n')
				continue;
			linha[i] = 0;
			break;
		}
		if (strcmp(cmp, linha) == 0) {
			fclose(fleitura);
			return 0;
		}
		if(feof(fleitura))
			break;
	}
	fclose(fleitura);
	return 1;
}

char ChecaLogin (User *usuario) {
	char linha[80]= {0};
	int check = 0;
	FILE * fcheca_login = fopen("Dados/login.txt", "r");

	if(fcheca_login == NULL) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	for (int i=0; i<strlen(usuario->login); i++) {
		if (usuario->login[i] == ':' || strlen(usuario->login) == 0)
			check++;
	}
	while (!feof(fcheca_login)) {
		fgets(linha, 57, fcheca_login);
		strtok(linha, ":");

		if (strcmp(linha, usuario->login) == 0 || check) {
			fclose(fcheca_login);
			return 1;
		}
	}
	fclose(fcheca_login);
	return 0;
}

char VirarAdmin (User *usuario) {
	char linha[80]= {0}, check[80] = {0};
	long int inicioLinha=0;
	int tam, cont = 0, i = 0;
	FILE * fleitura = fopen("Dados/login.txt", "r+");

	if (fleitura == NULL) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	ClearScreen();
	inicioLinha = ftell( fleitura );

	while (!feof(fleitura)) {
		memset(check, 0, 80);
		memset(linha, 0, 80);
		fgets(linha, 80, fleitura);

		for (size_t i = 0; i<80; i++) {
			if(linha[i] != '\n')
				continue;
			linha[i] = 0;
			break;
		}
		strcpy(check, linha);
		strtok(check, ":");

		if (strcmp(usuario->login, check) == 0) {
			tam = strlen(linha);
			fseek(fleitura, inicioLinha, SEEK_SET);

			for (i = 0; i < tam; i++) {
				if(linha[i] != ':') {
					putc((linha[i]), fleitura);
					continue;
				}
				cont++;
				putc((char) ':', fleitura);

				if (cont == 2)
					break;
			}
			i++;

			if (linha[i] == '1') {
				printf("O usuário ");
				printf(TC_RED);
				printf("%s", usuario->login);
				printf(TC_RST);
				printf(" já é administrador!\n");
			}
			else {
				printf("O usuário ");
				printf(TC_RED);
				printf("%s", usuario->login);
				printf(TC_RST);
				printf(" se tornou administrador!\n");
			}
			putc((char) '1', fleitura);

			printf("\nVoltando para o menu...\n");
			sleep(3);
			fclose(fleitura);
			return 0;
		}
		inicioLinha = ftell( fleitura );

		if (feof(fleitura)) {
			printf("O usuário ");
			printf(TC_RED);
			printf("%s", usuario->login);
			printf(TC_RST);
			printf(" não foi econtrado!\n");

			printf("\nVoltando para o menu...\n");
			sleep(3);
			fclose(fleitura);
			return 0;
		}
	}
	printf("O usuário ");
	printf(TC_RED);
	printf("%s", usuario->login);
	printf(TC_RST);
	printf(" não foi econtrado!\n");

	printf("\nVoltando para o menu...\n");
	sleep(3);
	fclose(fleitura);
	return 0;
}

char CriarAdmin (User *usuario) {
	char linha[80] = {0};
	char login[80] = {0};
	char senha[41] = {0};
	char cmp1[80] = {0};
	char cmp2[80] = {0};
	FILE * fleitura = fopen("Dados/login.txt", "r+");

	if (fleitura == NULL) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	ClearScreen();

	strcpy(cmp1, usuario->login);
	strcat(cmp1, ":");

	strcpy(senha, usuario->senha);
	memset(usuario->senha, 0, 41);
	Criptografar(senha);

	strcat(cmp1, senha);
	strcat(cmp1, ":");

	strcpy(cmp2, cmp1);
	strcat(cmp1, "0");
	strcat(cmp2, "1");

	while (!feof(fleitura)) {
		memset(linha, 0 , 80);
		fgets(linha, 80, fleitura);
		strcpy(login, linha);
		strtok(login, ":");

		for (size_t i = 0; i<80; i++) {
			if(linha[i] != '\n')
				continue;
			linha[i] = 0;
			break;
		}
		if (strcmp(cmp2, linha) == 0) {
			printf("O usuário ");
			printf(TC_RED);
			printf("%s", usuario->login);
			printf(TC_RST);
			printf(" já é administrador!\n");

			printf("\nVoltando para o menu...\n");
			sleep(3);
			fclose(fleitura);
			return 0;
		}
		if (strcmp(usuario->login, login) == 0) {
			char escolha;
			int opc = 0;

			tc_echo_off();
			tc_canon_off();
			HideCursor();
			do {
				SetCursorPosition(1, 1);
				printf(TC_RST);
				printf("O usuário ");
				printf(TC_RED);
				printf("%s", usuario->login);
				printf(TC_RST);
				printf(" já existe!\n");
				printf(TC_GRN);
				printf("Deseja tornar o usuário ");
				printf(TC_RED);
				printf("%s", usuario->login);
				printf(TC_RST);
				printf(" um administrador?\n\n");

				if (!opc) {
					printf(TC_RED);
					printf("   SIM\n");
					printf(TC_GRN);
					printf("   NÃO\n");
				}
				else {
					printf("   SIM\n");
					printf(TC_RED);
					printf("   NÃO\n");
				}
				escolha = getchar();

				if (escolha == 65 && opc > 0)
					opc--;
				if (escolha == 66 && opc < 1)
					opc++;

			} while (escolha != 10);

			printf(TC_RST);

			if (!opc)
				VirarAdmin(usuario);
			fclose(fleitura);
			return 0;
		}
		if (feof(fleitura)) {
			fprintf(fleitura, "%s\n", cmp2);
			printf("O usuário ");
			printf(TC_RED);
			printf("%s", usuario->login);
			printf(TC_RST);
			printf(" foi criado como administrador!\n");

			printf("\nVoltando para o menu...\n");
			sleep(3);
			fclose(fleitura);
			return 0;
		}
	}
	fprintf(fleitura, "%s\n", cmp2);
	printf("O usuário ");
	printf(TC_RED);
	printf("%s", usuario->login);
	printf(TC_RST);
	printf(" foi criado como administrador!\n");

	printf("\nVoltando para o menu...\n");
	sleep(3);
	fclose(fleitura);
	return 0;
}

#endif
