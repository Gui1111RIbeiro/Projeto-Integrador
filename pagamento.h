#ifndef _PAGAMENTO_
#define _PAGAMENTO_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "../Animacoes/Funcoes_Anin/term.h"
#include "../Listas/structs.h"

//-------------------FUNCIONALIDADES--------------------

char AdicionarCartao (User *usuario, char verificador);
void RemoverCartao (User *usuario, int cartao[16], char verificador);
char MeusCartoes (User *usuario, char verificador);
void VerFundos ();
void PrintCartao (int cartao[16], int data[4], char titular[28], int cvv[3], char erro);
char ValidarPagamento (User *usuario, int cartao[16]);
char VerificarCartao (User *usuario, int cartao[16]);
char Checa_mm_aa (int data[4], char check);

//-----------------------FUNÇÕES------------------------

char AdicionarCartao (User *usuario, char verificador) {
	int data, check, status, j = 0;
	int cartao_i[16] = {0};
	int cartao_o[16] = {0};
	int data_i[4] = {0};
	int data_o[4] = {0};
	int cvv_i[3] = {0};
	int cvv_o[3] = {0};
	char titular[28] = {0};
	char ch; 

	if (VerificarCartao(usuario, cartao_i)) {
		char escolha;
		int opc = 0;

		ClearScreen();

		do {
			printf(TC_GRN);
			printf("Você já têm o máximo de cartões registados!\nDeseja remover algum?\n\n");

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

		switch(opc) {
			case 0:
				MeusCartoes(usuario, 'R');
				printf("\nPressione qualquer tecla para continuar...\n");
				getchar();
				ClearScreen();
				break;
			case 1:
				printf("\nVoltando para o menu...\n");
				sleep(4);
				return 1;
		}
	}
	FILE * fregistro = fopen("Dados/cartoes.txt", "a");

	if (!fregistro) {
		printf("Falha ao adicionar o cartão\n");
		sleep(3);
		exit(1);
	}
	ClearScreen();
	printf(TC_RST);

	while (j < 17) {
		PrintCartao(cartao_i, data_i, titular, cvv_i, 'C');
		ch = getchar();

		if (ch == 27) {
			if (!kbhit())
				return 0;
			getchar();
			ch = getchar();
		}
		if (ch == 10 && j == 16)
			break;
		if (j == 0)
			if (ch < '3' || ch > '5')
				continue;

		if (ch >= '0' && ch <= '9' && j < 16) {
			cartao_i[j] = ch;
			cartao_o[j] = CriptoRSA(cartao_i[j] - '0', 2);
			j++;
		}
		if (ch == 127) {
			if(!j)
				continue;
			--j;
			cartao_i[j] = 0;
			cartao_o[j] = 0;
		}
		if (j == 16) {
			status = VerificarCartao(usuario, cartao_i);

			if (status == 1)
				continue;
			for(int a = 0; a < j; a++) {
				if (a == 0) {
					PrintCartao(cartao_i, data_i, titular, cvv_i, 'E');
					printf(TC_YEL);
					if (status == 2)
						printf("\n    ERRO-Cartão já cadastrado!!!\n");
						else
							printf("\n    ERRO-Cartão inválido!!!\n");
						printf(TC_RST);
					printf("    Pressione qualquer tecla para continuar...\n");
					getchar();
					ClearScreen();
				}
			}
			--j;
			cartao_i[j] = 0;
			cartao_i[j] = 0;
		}
	}
	j = 0;

	while(j < 5) {
		PrintCartao(cartao_i, data_i, titular, cvv_i,'D');
		ch = getchar();

		if (ch == 27) {
			if (!kbhit())
				return 0;
			getchar();
			ch = getchar();
		}
		if (ch == 10 && j == 4) {
			if(!Checa_mm_aa(data_i, 'A')) {
				for (int i = 0; i < 4; i++)
					data_i[i] = data_o[i] = 0;
				j = 0;
			}
			else
				break;
		}
		if (ch == 127) {
			if (!j)
				continue;
			--j;
			data_i[j] = 0;
			data_o[j] = 0;
			continue;
		}
		if (ch < '0' || ch > '9' || j == 4)
			continue;  
		data_i[j] = ch;
		data_o[j] = CriptoRSA(data_i[j] - '0', 2);
		j++;
	}
	j = 0;
	ShowCursor();

	while (j < 28) {
		PrintCartao(cartao_i, data_i, titular, cvv_i,'T');
		SetCursorPosition(j + 3, 5);
		ch = getchar();

		if (ch == 27) {
			if (!kbhit())
				return 0;
			getchar();
			ch = getchar();
		}
		if (ch == 10)
			break;
		if (ch == 127) {
			if(!j)
				continue;
			--j;
			titular[j] = 0;
		}
		if (j == 27)
			continue;
		if (ch >= 'a'  && ch <= 'z') {
			titular[j] = ch - 32;
			j++;
		}
		if (ch >= 'A' && ch <= 'Z' || ch == 32) {
			titular[j] = ch;
			j++;
		}
	}
	j = 0;
	HideCursor();
	PrintCartao(cartao_i, data_i, titular, cvv_i,'A');

	while (j < 4) {
		PrintCartao(cartao_i, data_i, titular, cvv_i,'B');
		ch = getchar();

		if (ch == 27) {
			if (!kbhit())
				return 0;
			getchar();
			ch = getchar();
		}
		if (ch == 10 && j == 3)
			break;
		if (ch == 127) {
			if (!j)
				continue;
			--j;
			cvv_i[j] = 0;
			cvv_o[j] = 0;
		}
		if (ch < '0' || ch > '9' || j == 3)
			continue;
		cvv_i[j] = ch;
		cvv_o[j] = CriptoRSA(cvv_i[j]-'0', 2);
		j++;
	}
	if (verificador == 'P') {
		FILE *fpagar = fopen("Dados/fundos.txt", "a");

		for (int i = 0; i < 16; i++)
			fprintf(fpagar, "%c", cartao_o[i]);
		fclose(fpagar);
	}
	fprintf(fregistro, "%s:", usuario->login);

	for (int i = 0; i < 16; i++)
		fprintf(fregistro, "%c", cartao_o[i]);
	fprintf(fregistro, ":");

	for (int i = 0; i < 4; i++)
		fprintf(fregistro, "%c", data_o[i]);
	fprintf(fregistro, ":%s:", titular);

	for (int i = 0; i < 3; i++)
		fprintf(fregistro, "%c", cvv_o[i]);
	fprintf(fregistro, "\n");
	fclose(fregistro);

	printf("\nCartão ");
	printf(TC_GRN);
	printf("XXXX-XXXX-XXXX-");
	printf(TC_RED);
	printf("%d%d%d%d", cartao_i[12]-'0', cartao_i[13]-'0', cartao_i[14]-'0', cartao_i[15]-'0');
	printf(TC_RST);
	printf("\nRegistrado com Sucesso!\n");
	if (verificador == 'A')
		printf("\nVoltando para o menu...\n");
	sleep(3);
	return 1;
}

void RemoverCartao(User *usuario, int cartao[16], char verificador) {
	char linha[70] = {0};
	char cmp[70] = {0};
	char* ptr;
	int cont = 0;
	int i;

	if (verificador == 'E') {
		int opc = 0;
		char escolha;
		do {
			ClearScreen();
			printf(TC_GRN);
			printf("Tem certeza que deseja ");
	
			printf(TC_YEL);
			printf("Remover");

			printf(TC_GRN);
			printf(" o cartão com final ");

			printf(TC_RED);
			printf("%d%d%d%d", cartao[12], cartao[13], cartao[14], cartao[15]);
			printf(TC_GRN);
			printf(" ?\n\n");

			if (opc == 0) {
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

		switch (opc) {
			case 0:
				break;
			case 1:
				return;
		}
	}
	FILE * input = fopen("Dados/cartoes.txt", "r");
	FILE * output = fopen("Dados/transferindo.txt", "w+");

	if (!input || !output) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(input)) {
		i = 0;
		cont = 0;

		memset(cmp, 0, 70);
		memset(linha, 0, 70);
		fgets(linha, 70, input);

		strcpy(cmp, linha);
		ptr = strtok(cmp, ":");

		if (ptr == NULL)
			break;
		if (strcmp(cmp, usuario->login) == 0) {
			ptr = strtok(NULL, ":");

			for (int j = 0; j < 16; j++) {
				ptr[j] = DescriptoRSA(ptr[j], 2);
				if (ptr[j] == cartao[j])
					i++;
				else
					break;
			}
			if (i != 16) {
				for (int i = 0; i < 70; i++) {
					if (linha[i] == ':')
						cont++;
					if (cont < 8) {
						if (cont > 3)
							cont++;
						fprintf(output, "%c", linha[i]);
					}
				}
				fprintf(output, "\n");
			} 
		}
		else {
			for (int i = 0; i < 70; i++) {
				if (linha[i] == ':')
					cont++;
				if (cont < 8) {
					if (cont > 3)
						cont++;
					fprintf(output, "%c", linha[i]);
				}
			}
			fprintf(output, "\n");
		}
	}
	fclose(input);
	fclose(output);

	remove("Dados/cartoes.txt");
	rename("Dados/transferindo.txt", "Dados/cartoes.txt");

	if (verificador == 'B') {
		printf(TC_RED);
		printf("\nCartão com final %d%d%d%d\nFoi bloqueado!!!\n", cartao[12], cartao[13], cartao[14], cartao[15]);
		printf(TC_RST);
	}
	else {
		printf("\n\nCartão com final ");
		printf(TC_RED);
		printf("%d%d%d%d", cartao[12], cartao[13], cartao[14], cartao[15]);
		printf(TC_RST);
		printf("\nRemovido com Sucesso!\n");
	}
}

char MeusCartoes (User *usuario, char verificador) {
	char linha[80] = {0};
	char *ptr;
	char cartoes[5][80];
	int cont = 0;
	FILE * fleitura = fopen("Dados/cartoes.txt", "rt");

	if (!fleitura) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	ClearScreen();

	while (!feof(fleitura)) {
		memset(linha, 0, 80);
		fgets(linha, 80, fleitura);

		ptr = strtok(linha, ":");

		if (ptr == NULL)
			break;
		if (strcmp(ptr, usuario->login) == 0) {
			ptr = strtok(NULL, ":");

			for (int i = 0; i < 16; i++)
				cartoes[cont][i] = DescriptoRSA(ptr[i], 2);
			if (verificador == 'O') {
				if (!cont)
					printf("Cartões salvos...\n");
				printf("\n  %d - ", cont+1);
				printf(TC_GRN);
				printf("Cartão XXXX-XXXX-XXXX-");
				printf(TC_RED);
				printf("%d%d%d%d", cartoes[cont][12], cartoes[cont][13], cartoes[cont][14], cartoes[cont][15]);
				printf(TC_RST);
			}
			cont++;
		}
	}
	fclose(fleitura);

	if (verificador != 'O' && cont) {
		char escolha;
		int status;
		int opc;
		int check;
		int jump;
		int fim = 0;
		int cartao[16] = {0};

		while (!fim) {
			opc = 0;
			ClearScreen();

			if (!cont) {
				printf(TC_YEL);
				printf("Todos os cartões foram inválidos!!!\nAdicione algum válido!\n");
				printf(TC_RST);
				printf("\nPressione qualquer tecla  para inserir um novo cartão... \n");
				getchar();

				if (!AdicionarCartao(usuario, 'P'))
					return 0;
				return 1;
			}
			do {
				jump = 0;
				SetCursorPosition(1, 1);
				printf(TC_GRN);
				printf("Escolha o cartão para ");
				printf(TC_YEL);

				if (verificador != 'D')
					printf("pagar!\n");
				else
					printf("remover!\n");

				for (int i = 0; i < cont; i++) {
					check = 0;
					if (opc == i)
						printf(TC_RED);
					else
						printf(TC_GRN);
					while (cartoes[i+jump][0] == 0)
						jump++;
					printf("\n   %d - Cartão XXXX-XXXX-XXXX-%d%d%d%d", i+1, cartoes[i+jump][12], cartoes[i+jump][13], cartoes[i+jump][14], cartoes[i+jump][15]);
				}
				escolha = getchar();

				if (escolha == 27) {
					if (!kbhit())
						return 0;
					getchar();
					escolha = getchar();
					if (escolha == 'A' && opc > 0)
						opc--;
					else
						if (escolha == 'B' && opc < cont-1)
							opc++;
				}

			} while (escolha != 10);

			printf(TC_RST);

			for (int i = 0; i < 16; i++) {
				if (i == 0) {
					while (cartoes[opc][i] == 0)
						opc++;
				}
				cartao[i] = cartoes[opc][i];
			}
			if (verificador == 'P' || verificador == 'R') {
				printf(TC_GRN);
				printf("\n\nValidando Pagamento...\n");
				printf(TC_RST);
				sleep(2);

				status = ValidarPagamento(usuario, cartao);
				if (status == 3) {
					opc++;
					continue;
				}
				for (int i = 0; i < 16; i ++) {
					if (i == 0) {
						while (cartoes[opc][i] == 0)
							opc++;
					}
					if (cartao[i] == cartoes[opc][i])
						cartoes[opc][i] = 0;
				}
				cont--;

				if (!status) {
					printf(TC_YEL);
					printf("\n\nData de validade do cartão vencida!\nRemovendo o cartão vencido...");
					printf(TC_RST);
					RemoverCartao(usuario, cartao, 'R');

					printf("\nPressione qualquer tecla  para tentar de novo... \n");
					getchar();
					continue;
				}
				if (status == 1) {
					RemoverCartao(usuario, cartao, 'B');
					printf("\nPressione qualquer tecla para usar outro... \n");
					getchar();
					continue;
				}
				if (status == 2) {
					FILE *fpagar = fopen("Dados/fundos.txt", "a");

					if (!fpagar)
						exit(1);
					fprintf(fpagar, "%s", usuario->login);
					if (verificador == 'R')
						fprintf(fpagar, "%s:", usuario->login);
					for (int i = 0; i < 16; i++) {
						cartoes[opc][i] = CriptoRSA(cartao[i], 2);
						fprintf(fpagar, "%c", cartoes[opc][i]);
					}
					fclose(fpagar);
					return 1;
				}
			}
			else {
				RemoverCartao(usuario, cartao, 'E');
				printf("\nVoltando para o menu...\n");
				sleep(4);
				return 1;	
			}
		}
	}

	if (!cont && verificador != 'P' && verificador != 'R') {
		char escolha;
		int opc = 0;

		do {
			SetCursorPosition(1, 1);
			printf(TC_GRN);

			printf("Nenhum cartão foi encontrado!\nDeseja adicionar um novo?\n\n");

			if (opc == 0) {
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

		switch (opc) {
			case 0:
				AdicionarCartao(usuario, 'A');
				break;
			case 1:
				printf("\nVoltando para o menu...\n");
				sleep(4);
				break;
		}
		return 1;
	}
	if ((verificador == 'P' || verificador == 'R') && !cont) {
		printf(TC_YEL);
		printf("Nenhum cartão foi encontrado!\nAdicione um novo cartão\n");
		sleep(3);
		if (!AdicionarCartao(usuario, 'P'))
			return 0;
		return 1;
	}
	printf("\n\nPressione qualquer tecla para voltar... \n");
	getchar();
	printf("\nVoltando para o menu...\n");
	sleep(4);
}

void VerFundos () {
	char linha[100] = {0};
	char check[100] = {0};
	char *ptr;
	int carry;
	int fundos = 0;
	FILE *fpagamento = fopen("Dados/fundos.txt", "r");

	if (!fpagamento) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(fpagamento)) {
		carry = 0;
		ptr = NULL;

		memset(linha, 0, 100);
		memset(check, 0, 100);
		fgets(linha, 100, fpagamento);

		strcpy(check, linha);
		ptr = strtok(check, ":");

		if (ptr == NULL)
			break;
		ptr = strtok(NULL, ":");
		ptr = strtok(NULL, ":");
		ptr = strtok(NULL, ":");
		ptr = strtok(NULL, ":");
		ptr = strtok(NULL, ":");
		carry = atoi(ptr);

		fundos = fundos + carry;
	}
	fclose(fpagamento);

	ClearScreen();

	printf(TC_GRN);
	printf("Nossa empresa tem atualmente...\n   R$ ");
	printf(TC_RED);
	printf("%d,00\n", fundos);
	printf(TC_RST);

	printf("\n\nPressione qualquer tecla para voltar... \n");
	getchar();
}

void PrintCartao (int cartao[16], int data[4], char titular[28], int cvv[3], char check) {
	char linha[93] = {0};
	int cont = 0;
	int i;
	int j;
	FILE * fprint = fopen("Animacoes/Textos_Anin/cartao_anin.txt", "rt");

	if (!fprint) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	SetCursorPosition(1, 1);

	while (!feof(fprint)) {
		memset(linha, 0, 93);
		fgets(linha, 93, fprint);
		i = 0;
		j = 0;

		if (linha[i] == 'F') {
			if (check == 'A') {
				ClearScreen();
				usleep(700000);
				cont++;
				continue;
			}
			if (cont == 50)
				break;
			if (check == 'B') {
				cont++;
				continue;
			}
			if (check != 'B')
				break;
		}
		if (check == 'B' && cont < 44) {
			cont++;
			continue;
		}
		if (check == 'A' && cont < 10) {
			cont++;
			continue;
		}
		if (check == 'A' && cont > 43)
			break;
		if (check == 'A') {
			cont++;

			if (cont == 14) {
				while (i < strlen(linha)) {
					if (linha[i] == 'X') {
						printf("%d", cartao[j+14]-'0');
						j++;
					}
					else
						printf("%c", linha[i]);
					i++;
				}
				continue;
			}
			if (cont == 15) {
				while (i < strlen(linha)) {
					if (linha[i] == 'X') {
						printf("%d", cartao[j+5]-'0');
						j++;
					}
					else
						printf("%c", linha[i]);
					i++;
				}
				continue;
			}
			if (cont == 16) {
				while (i < strlen(linha)) {
					if (linha[i] == 'X') {
						printf("%d", cartao[j]-'0');
						j++;
					}
					else
						if (linha[i] == 'm') {
							printf("%d%d/%d%d", data[0]-'0', data[1]-'0', data[2]-'0', data[3]-'0');
							j = 0;
							i = i + 4;
					}
					else
						if (linha[i] == 't') {
							if (titular[j+20] == 0)
								printf(" ");
							else
							printf("%c",titular[j+20]);
							j++;
						}
					else
						printf("%c", linha[i]);
					i++;
				}
				continue;
			}
			if (cont == 17) {
				while (i < strlen(linha)) {
					if (linha[i] == 't') {
						if (titular[j+8] == 0)
							printf(" ");
						else
							printf("%c", titular[j+8]);
						j++;
					}
					else
						if (linha[i] == 'y') {
							if (cartao[0]-'0' == 3) {
								printf(TC_GRY);
								printf("   elo");
							}
							if (cartao[0]-'0' == 4) {
								printf(TC_BLU);
								printf("  Visa");
							}
							if (cartao[0]-'0' == 5){
								printf(TC_YEL);
								printf("er");
								printf(TC_RED);
								printf("Card");
							}
							i = i + 5;
							printf(TC_RST);
						}
					else
						printf("%c", linha[i]);
					i++;
				}
				continue;
			}
			if (cont == 18) {
				while (i < strlen(linha)) {
					if (linha[i] == 't') {
						if (titular[j] == 0)
							printf(" ");
						else
							printf("%c", titular[j]);
						j++;
					}
					else
						if (linha[i] == 'y') {
							if (cartao[0]-'0' == 5) {
								printf(TC_YEL);
								printf("Mast");
								printf(TC_RST);
							}
							else
								printf("    ");
							i = i + 3;
						}
					else
						printf("%c", linha[i]);
					i++;
				}
				continue;
			}
			if (cont == 40){
				while (i < strlen(linha)){
					if(linha[i] == 'X')
						printf(TC_GRN);
					if (i == 30)
						printf(TC_RST);
					printf("%c", linha[i]);
					i++;
				}
				continue;
			}
			printf("%s", linha);
			continue;
		}
		if (cont == 3) {
			while (i < strlen(linha)) {
				if (linha[i] == 'X') {
					if (check == 'E' && j == 0)
						printf(TC_RED);
					if (check == 'C' && j == 0)
						printf(TC_GRN);
					if (cartao[j] != 0)
						printf("%d", cartao[j]-'0');
					else
						printf("%c", linha[i]);
					j++;
				}
				else
					printf("%c", linha[i]);
				if (i == 30)
					printf(TC_RST);
				i++;
			}
			cont++;
			continue;
		}
		if (cont == 4) {
			while (i < strlen(linha)) {
				if (linha[i] == 'm' || linha[i] == 'a') {
					if (check == 'D' && j == 0)
						printf(TC_GRN);
					if (data[j] != 0)
						printf("%d", data[j]-'0');
					else
						printf("%c", linha[i]);
					j++;
				}
				else
					printf("%c", linha[i]);
				if (i == 30)
					printf(TC_RST);
				i++;
			}
			cont++;
			continue;
		}
		if (cont == 5) {
			while (i < strlen(linha)) {
				if (i > 3 && i < 31) {
					if (check == 'T' && j == 0)
						printf(TC_GRN);
					if (titular[j] != 0)
						printf("%c", titular[j]);
					else
						printf("%c", linha[i]);
					j++;
				}
				else
					printf("%c", linha[i]);
				if (i == 30)
					printf(TC_RST);
				i++;
			}
			cont++;
			continue;
		}
		if (cont == 6 ) {
			while (i < strlen(linha)) {
				if (i > 19 && i < 28) {
					if (cartao[0] == 0)
						printf("%c", linha[i]);
					else {
						switch(cartao[0]-'0') {
							case 3:
								printf(TC_GRY);
								printf("%7selo", "");
								i = i + 9;
								break;
							case 4:
								printf(TC_BLU);
								printf("%6sVisa", "");
								i = i + 9;
								break;
							case 5:
								printf(TC_YEL);
								printf("Master");
								printf(TC_RED);
								printf("Card");
								i = i + 9;
								break;
						}
						printf(TC_RST);
					}
				}
				else
					printf("%c", linha[i]);
				i++;
			}
			cont++;
			continue;
		}
		j = 0;
		if (cont == 51) {
			while (i < strlen(linha)) {
				if (linha[i] == 'X') {
					if (check == 'B' && j == 0)
						printf(TC_GRN);
					if (cvv[j] != 0)
						printf("%d", cvv[j]-'0');
					else
						printf("%c", linha[i]);
					j++;
				}
				else
					printf("%c", linha[i]);
				if (i == 30 && j > 0)
					printf(TC_RST);
				i++;
			}
			cont++;
			continue;
		}
		printf("%s", linha);
		cont++;
		continue;
	}
	fclose(fprint);
}

char VerificarCartao (User *usuario, int cartao[16]) {
	int verificador = 0;
	int quant = 0;
	int cont;
	int check[16];
	char linha[80];
	char *ptr;
	FILE *fleitura = fopen("Dados/cartoes.txt", "r");

	if (!fleitura) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(fleitura)) {
		cont = 0;
		memset(linha, 0, 80);
		fgets(linha, 80, fleitura);

		ptr = strtok(linha, ":");

		if(ptr == NULL)
			break;
		if (strcmp (ptr, usuario->login) == 0) {
			ptr = strtok(NULL, ":");
			quant++;
			for (int i = 0; i < 16; i++) {
				ptr[i] = DescriptoRSA(ptr[i], 2);
				if (ptr[i] == (cartao[i]-'0'))
					cont++;
			}
		}
		if (cont == 16)
			return 2;
		if (quant == 5)
			return 1;
	}
	if (cartao[0] == 0)
		return 0;

	for (int i = 0; i < 15; i++) {
		if (i+1 % 2 == 0)
			check[i] = (cartao[i]-'0');
		else 
			check[i] = (cartao[i]-'0') * 2;
	}
	for (int i = 0; i < 15; i++)
		verificador = verificador + check[i];
	while (verificador != 0) {
		if (verificador > 10)
			verificador = verificador - 10;
		else {
			verificador--;
			cont++;
		}
	}
	if (cont >= 5)
		cont = 10 - cont;
	if ((cartao[15]-'0') == cont)
		return 1;
	else
		return 0;
}

char ValidarPagamento (User *usuario, int cartao[16]) {
	char titular[80] = {0};
	char linha[80] = {0};
	char status;
	char ch;
	int cmp_cartao[16] = {0};
	int cmp_cvv[3] = {0};
	int data[4] = {0};
	int cvv[3] = {0};
	int tentativa = 0;
	int j = 0;
	int increment;
	int cont;
	FILE *fcheck = fopen("Dados/cartoes.txt", "rt");

	if (!fcheck) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(fcheck)) {
		cont = 0;
		memset(linha, 0, 80);
		memset(titular, 0, 28);
		fgets(linha, 80, fcheck);

		strcpy(titular, linha);
		strtok(titular, ":");

		if (strcmp (titular, usuario->login) == 0) {

			for (int i = 0; i < 16; i++) {
				cmp_cartao[i] = DescriptoRSA(linha[i+1+strlen(titular)], 2);
				if (cmp_cartao[i] == cartao[i])
					cont++;
			}
		}
		if (cont == 16)
			break;
	}
	fclose(fcheck);
	increment = strlen(titular) + 1;

	for (int i = 0; i < 4; i++)
		data[i] = DescriptoRSA(linha[i + 17 + increment], 2);
	status = Checa_mm_aa(data, 'V');

	if (!status)
		return 0;

	for (int i = increment; i < strlen(linha); i++) {
		if (linha[i+24] == ':') {
			increment++;
			break;
		}
		increment++;;
	}
	increment = increment + 24;
	do {
		ClearScreen();

		while(j < 4) {
			PrintCartao(cartao, data, titular, cvv,'B');
			ch = getchar();

			if (ch == 27) {
				if (!kbhit())
					return 3;
				getchar();
				ch = getchar();
			}
			if (ch == 10 && j == 3)
				break;
			if (ch == 127) {
				if (!j)
					continue;
				--j;
				cvv[j] = 0;
			}
			if (ch < '0' || ch > '9' || j == 3)
				continue;
			cvv[j] = ch;
			j++;
		}
		if (tentativa == 3)
			break;
		for (int i = 0; i < 3; i++) {
			cmp_cvv[i] = DescriptoRSA(linha[i + increment], 2);
			if (cmp_cvv[i] != cvv[i]-'0') {
				printf(TC_RED);
				printf("\nCVV incorreto!\n");
				printf(TC_YEL);
				printf("Restam mais ");
				printf(TC_RED);
				printf("%d", 2 - tentativa);
				printf(TC_YEL);
				printf(" tentativas\n");
				printf(TC_RST);

				if (tentativa < 2) {
					printf("\nPressione qualquer tecla para tentar de novo...");
					getchar();
				}
				for (int i = 0; i < 3; i++)
					cvv[i] = 0;
				j = 0;
				tentativa++;
				break;
			}
		}
		if (j == 0)
			continue;
		return 2;
	} while (tentativa < 3);

	return 1;
}

char Checa_mm_aa (int mm_aa[4], char check) {
	int verificador = 0;
	int resp;

	struct tm *data;  

	time_t segundos;
	time(&segundos);   

	data = localtime(&segundos);

	if (check == 'A')
		resp = (((mm_aa[2]-'0') *10) + (mm_aa[3]-'0')) + 100;
	else
		resp = ((mm_aa[2] *10) + mm_aa[3]) + 100;

	if (resp == data->tm_year)
		verificador++;
	if (resp < data->tm_year || resp > data->tm_year + 5) {
		if (check == 'V')
			return 0;
		ClearScreen();
		printf(TC_YEL);
		printf("Data inválida!");
		printf("\nTente um ano válido!\n");
		printf(TC_RST);

		sleep(3);
		return 0;
	}
	else {
		if (check == 'A')
			resp = (((mm_aa[0]-'0') *10) + (mm_aa[1]-'0'));
		else
			resp = ((mm_aa[0] *10) + mm_aa[1]);

		if (verificador) {
			if (resp < data->tm_mon+1|| resp > 12) {
				if (check == 'V')
					return 0;
				ClearScreen();
				printf(TC_YEL);
				printf("Data inválida!");
				printf("\nTente um mês válido!\n");
				printf(TC_RST);

				sleep(3);
				return 0;
			}
		}
		else {
			if (resp < 0 || resp > 12) {
				ClearScreen();
				printf(TC_YEL);
				printf("Data inválida!");
				printf("\nTente um mês válido!\n");
				printf(TC_RST);

				sleep(3);
				return 0;
			}
		}
	}
	return 1;
}

#endif
