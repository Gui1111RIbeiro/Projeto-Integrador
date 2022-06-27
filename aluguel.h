#ifndef _ALUGUEL_
#define _ALUGUEL_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "biblioteca.h"
#include "pagamento.h"
#include "../Animacoes/term.h"
#include "../Listas/structs.h"
#include "../Animacoes/desenharLivro.h"

//-------------------FUNCIONALIDADES--------------------

void AlugarLivro (User *usuario, unsigned long long cod);
void DevolverLivro (User *usuario, unsigned long long cod);
void RenovarLivro (User *usuario, unsigned long long cod);
void MeusLivros (User *usuario, char verificador);
char ChecaDia (User *usuario);
char ChecaAluguel (User *usuario, unsigned long long cod);

//-----------------------FUNÇÕES------------------------

void AlugarLivro (User *usuario, unsigned long long cod) {
	char escolha;
	int check = 0;
	int opc = 0;
	Livro livro;
	FILE * fpagamento = fopen("Dados/fundos.txt", "a");
	livro = BuscarLivroCod(cod);

	struct tm *data;

	time_t segundos;
	time(&segundos);

	data = localtime(&segundos);

	if (!fpagamento) {
		exit(1);
	}
	
	/*
	do {
		check = ChecaAluguel(usuario, cod);

		if (!check) {
			ClearScreen();
			printf("Você já Alugou o livro %s", livro.titulo);
			printf("\nPor favor escolha outro!\n");
			sleep(3);
			ClearScreen();
			return;
		}
		if (check == 2) {
			do {
				SetCursorPosition(1, 1);
				printf(TC_GRN);
				printf("Você já têm o máximo de livros alugados!\nDeseja remover algum?\n\n");

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

			switch (opc) {
				case 0:
					MeusLivros(usuario, 'D');
					printf("\nPressione qualquer tecla para continuar...\n");
					getchar();
					check = 1;
					ClearScreen();
					break;
				case 1:
					printf("\nVoltando para o menu...\n");
					sleep(4);
					return;
			}
		}
	} while (!check || check == 2);*/
	char preco[13] = {0};
	preco[0] = 'R';
	preco[1] = '$';
	gcvt(livro.preco, 10, &preco[2]);
	do {

		DrawBegin();
		DrawTextSpace('l');
		DrawTextLeft("Livro:", TC_GRN);
		DrawTextLeft(livro.titulo, TC_BLK);
		DrawTextSpace('l');
		DrawTextSpace('l');
		DrawTextLeft("Custo do aluguel:", TC_GRN);
		DrawTextLeft(preco, TC_BLK);


		DrawTextSpace('r');
		DrawTextRight("Deseja alugar?", TC_BLK);
		DrawTextSpace('r');
		DrawTextSpace('r');
		DrawTextRight("[SIM]", !opc ? TC_RED : TC_GRN);
		DrawTextSpace('r');
		DrawTextSpace('r');
		DrawTextRight("[NAO]", opc ? TC_RED : TC_GRN);

		SaveText(0);
		DrawEnd();
		
		escolha = getchar();

		if(escolha == 27){
			if(kbhit()){
				getchar();
				escolha = getchar();
				if (escolha == 'A' && opc)
					opc--;
				if (escolha == 'B' && !opc)
					opc++;
			}
		}

	} while (escolha != 10);

	if (!opc) {
		fprintf(fpagamento, "%s:", usuario->login);
		fclose(fpagamento);
		MeusCartoes(usuario, 'P');
	}
	else {
		fclose(fpagamento);
		return;
	}
	FILE * fregistro = fopen("Dados/aluguel.txt", "a");
	FILE * fpagar = fopen("Dados/fundos.txt", "a");

	fprintf(fregistro, "%s:%llu:%i:%i\n", usuario->login, cod, data->tm_yday, data->tm_year+1900);


	fprintf(fpagar, ":Data = %d/%d/%d; Hora = %d:%d:%d:%.2f\n", data->tm_mday, data->tm_mon+1, data->tm_year+1900, data->tm_hour-3, data->tm_min, data->tm_sec, livro.preco);
	fclose(fregistro);
	fclose(fpagar);

	livro.alugado++; //Aumentar o aluguel
	AttLivro(livro);

	DrawBegin();
	LoadText();
	DrawTextSpace('r');
	DrawTextSpace('r');
	DrawTextRight("Sucesso.", TC_YEL);
	DrawEnd();
	sleep(3);
	return;
}

void DevolverLivro (User *usuario, unsigned long long cod) {
	char linha[80] = {0};
	char login[80] = {0};
	char cmp[30] = {0};
	char* ptr;
	Livro livro;
	FILE * input = fopen("Dados/aluguel.txt", "r");
	FILE * output = fopen("Dados/transferindo.txt", "w");

	NumToStr(cod, cmp, 10);
	HideCursor();

	if (!input || !output) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(input)) {
		memset(login, 0, 80);
		memset(linha, 0, 80);
		fgets(linha, 80, input);

		strcpy(login, linha);
		ptr = strtok(login, ":");

		if (ptr == NULL)
			break;
		if(strcmp(login, usuario->login) == 0) {
			ptr = strtok(NULL, ":");
			strcpy(login, ptr);

			if(strcmp(cmp, login) != 0)
				fputs(linha, output);
		}
		else
			fputs(linha, output);
	}
	fclose(input);
	fclose(output);

	livro = BuscarLivroCod(cod);
	livro.alugado--; //diminuir o aluguel
	AttLivro(livro);

	remove("Dados/aluguel.txt");
	rename("Dados/transferindo.txt", "Dados/aluguel.txt");

	return;
}

void RenovarLivro (User *usuario, unsigned long long cod){
	char linha[80] = {0};
	char check[80] = {0};
	char cmp[10] = {0};
	char codigo[10] = {0};
	char dia[10] = {0};
	char ano[6] = {0};
	int cont = 0;
	long int inicioLinha;
	Livro livro;
	FILE * fleitura = fopen("Dados/aluguel.txt", "r+");
	FILE *fpagar = fopen("Dados/fundos.txt", "a");

	struct tm *data;

	time_t segundos;
	time(&segundos);

	data = localtime(&segundos);

	NumToStr(data->tm_yday, dia, 10);
	NumToStr(data->tm_year+1900, ano, 10);
	NumToStr(cod, cmp, 10);
	strcat(dia, ":");
	strcat(dia, ano);
	strtok(dia, "\n");
	HideCursor();

	if (!fleitura || !fpagar) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	inicioLinha = ftell( fleitura );

	while (!feof(fleitura)) {
		cont = 0;
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

		if (strcmp(check, usuario->login) == 0) {
			for (int i = strlen(check); i < strlen(linha); i++) {
				if (linha[i] == ':') {
					cont++;
					continue;
				}
				if (cont == 2)
					break;
				codigo[cont - 1] = linha[i];
			}
			cont = 0;

			if (strcmp(codigo, cmp) == 0) {
				fseek(fleitura, inicioLinha, SEEK_SET);
				livro = BuscarLivroCod(cod);

				for (int i = 0; i < strlen(linha); i++) {
					if (linha[i] == ':') {
						cont++;
						fputc(linha[i], fleitura);
						continue;
					}
					if (cont == 2)
						break;
					fputc(linha[i], fleitura);
				}
				for (int j = 0; j < strlen(dia); j++)
					fputc(dia[j], fleitura);
			}
		}
		inicioLinha = ftell( fleitura );

		if (feof(fleitura))
			break;
	}
	fprintf(fpagar, ":Data = %d/%d/%d; Hora = %d:%d:%d:%.2f\n", data->tm_mday, data->tm_mon+1, data->tm_year+1900, data->tm_hour-3, data->tm_min, data->tm_sec, livro.preco / 10);

	fclose(fpagar);
	fclose(fleitura);
	return;
}

void MeusLivros (User *usuario, char verificador) {
	char linha[80] = {0};
	char codigos[5][40] = {0};
	char titulos[5][40] = {0};
	char* ptr;
	int dias[5] = {0};
	int cont = 0;
	int check = 0;
	unsigned long long cod;
	Livro livro;
	FILE * fleitura = fopen("Dados/aluguel.txt", "r");

	struct tm *data;

	time_t segundos;
	time(&segundos);

	data = localtime(&segundos);

	if (!fleitura) {
		exit(90);
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
			strcpy (codigos[cont], ptr);
			cod = atoi(codigos[cont]);
			livro = BuscarLivroCod (cod);
			strcpy(titulos[cont], livro.titulo);

			ptr = strtok(NULL, ":");
			dias[cont] = atoi(ptr);

			if (verificador == 'O') {
				if (!cont)
					printf("Livros Alugados\n");
				printf(TC_RST);
				printf("\n   %d- ", cont+1);
				printf(TC_RED);
				printf("%s", titulos[cont]);
				printf(TC_RST);
				printf(" - restam ");
				printf(TC_YEL);

				if (dias[cont] > data->tm_yday)
					printf("%d dias", dias[cont] - (data->tm_yday + 358));
				else
					printf("%d dias", (7 + dias[cont]) - data->tm_yday);
			}
			if (dias[cont] == data->tm_yday)
				check++;
			cont++;
		}
	}
	fclose(fleitura);

	if ((verificador == 'D' || verificador == 'R') && cont) {
		char escolha;
		int opc = 0;
		int jump;

		if (cont == check && verificador == 'R') {
			printf(TC_YEL);
			printf("Você alugou todos os seus Livros hoje\nNão tem o porque renovar\n");
			printf(TC_RST);
			printf("\nPressione qualquer tecla para voltar... \n");
			getchar();
			return;
		}
		do {
			jump = 0;
			SetCursorPosition(1, 1);
			printf(TC_GRN);
			printf("Escolha o Livro para ");
			printf(TC_YEL);

			if (verificador == 'D')
				printf("remover!\n");
			else
				printf("renovar!\n");

			for (int i = 0; i < cont; i++) {
				if (dias[i] == data->tm_yday && verificador == 'R') {
					jump++;
					continue;
				}
				if (opc + jump == i)
					printf(TC_RED);
				else
					printf(TC_GRN);
				printf("\n   %d- %s", i + 1 - jump, titulos[i]);
				if (dias[i] > data->tm_yday)
					printf(" - restam %d dias", dias[i] - (data->tm_yday + 358));
				else
					printf(" - restam %d dias", (7 + dias[i]) - data->tm_yday);
			}
			escolha = getchar();

			if (escolha == 65 && opc > 0)
				opc--;
			if (escolha == 66 && opc < cont - 1 - jump)
				opc++;

		} while (escolha != 10);

		printf(TC_RST);
		jump = 0;

		for (int i = 0; i < cont; i++) {
			if (dias[i] == data->tm_yday && verificador == 'R') {
				jump++;
				continue;
			}
			if (opc + jump == i) {
				cod = atoi(codigos[opc + jump]);
				break;
			}
		}
		livro = BuscarLivroCod(cod);
		if (verificador == 'R') {
			int opc2 = 0;
			ClearScreen();

			do {
				SetCursorPosition(1, 1);
				printf(TC_GRN);
				printf("Deseja Renovar o aluguel do Livro ");

				printf(TC_RED);
				printf("%s", titulos[opc + jump]);

				printf(TC_GRN);
				printf("\nPor R$ ");

				printf(TC_RED);
				printf("%.2f", livro.preco / 10);

				printf(TC_GRN);
				printf(" apenas?\n\n");

				if (!opc2) {
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

				if (escolha == 65 && opc2 > 0)
					opc2--;
				if (escolha == 66 && opc2 < 1)
					opc2++;

			} while (escolha != 10);

			printf(TC_RST);

			if (opc2) {
				printf("\nVoltando para o menu...\n");
				sleep(3);
				ClearScreen();
				return;
			}
		}
		if (verificador == 'D') {
			DevolverLivro(usuario, cod);
			printf("\n\nLivro ");
			printf(TC_RED);
			printf("%s ", titulos[opc + jump]);
			printf(TC_RST);
			printf("devolvido com sucesso!\n");
		}
		else {
			MeusCartoes(usuario, 'R');
			RenovarLivro(usuario, cod);
			printf("\nLivro ");
			printf(TC_RED);
			printf("%s ", titulos[opc + jump]);
			printf(TC_RST);
			printf("renovado com sucesso!\n");
		}
		sleep(3);
		return;
	}
	else {
		printf(TC_YEL);
		if (!cont)
			printf("Você ainda não alugou nenhum livro");
		printf(TC_RST);
		printf("\n\nPressione qualquer tecla para voltar... \n");
		getchar();
	}
}

char ChecaDia (User *usuario) {
	char linha[80] = {0};
	char titulo[30] = {0};
	char codigo[30] = {0};
	char escolha;
	char* ptr;
	int dia;
	int ano;
	int opc;
	unsigned long long cod;
	Livro livro;
	FILE * fleitura = fopen("Dados/aluguel.txt", "r");

	struct tm *data;

	time_t segundos;
	time(&segundos);

	data = localtime(&segundos);

	if (!fleitura) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(fleitura)) {
		opc = 0;
		memset(linha, 0, 80);
		fgets(linha, 80, fleitura);

		ptr = strtok(linha, ":");

		if (ptr == NULL)
			break;
		if (strcmp(ptr, usuario->login) == 0) {
			ptr = strtok(NULL, ":");
			cod = atoi(ptr);

			livro = BuscarLivroCod (cod);
			strcpy(titulo, livro.titulo);

			ptr = strtok(NULL, ":");
			dia = atoi(ptr);

			ptr = strtok(NULL, ":");
			ano = atoi(ptr);

			if (dia > data->tm_yday) {
				if (dia >= data->tm_yday+358) {
					ClearScreen();

					do {
						SetCursorPosition(1, 1);
						printf(TC_GRN);
						printf("Livro ");

						printf(TC_RED);
						printf("%s", titulo);

						printf(TC_GRN);
						printf(" está fora do Prazo!!!\nDeseja Renovar o aluguel do Livro por R$ ");

						printf(TC_RED);
						printf("%.2f", livro.preco / 10);

						printf(TC_GRN);
						printf(" apenas?\n\n");

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
					fclose(fleitura);

					switch (opc) {
						case 0:
							MeusCartoes(usuario, 'R');
							RenovarLivro(usuario, cod);

							printf("\nLivro ");
							printf(TC_RED);
							printf("%s ", titulo);
							printf(TC_RST);
							printf("renovado com sucesso!\n");

							sleep(3);
							break;
						case 1:
							DevolverLivro(usuario, cod);

							printf("\nLivro ");
							printf(TC_RED);
							printf("%s ", titulo);
							printf(TC_RST);
							printf("devolvido com sucesso!\n");

							sleep(3);
							break;
					}
					printf("\nProcurando por mais livros fora do prazo...\n");
					sleep(3);
					return 0;
				}
			}
			else {
				if (dia +7 <= data->tm_yday || ano < data-> tm_year+1900) {
					ClearScreen();

					do {
						SetCursorPosition(1, 1);
						printf(TC_GRN);
						printf("Livro ");

						printf(TC_RED);
						printf("%s", titulo);

						printf(TC_GRN);
						printf(" está fora do Prazo!!!\nDeseja Renovar o aluguel do Livro por R$ ");

						printf(TC_RED);
						printf("%.2f", livro.preco / 10);

						printf(TC_GRN);
						printf(" apenas?\n\n");

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
					fclose(fleitura);

					switch (opc) {
						case 0:
							MeusCartoes(usuario, 'R');
							RenovarLivro(usuario, cod);

							printf("\nLivro ");
							printf(TC_RED);
							printf("%s ", titulo);
							printf(TC_RST);
							printf("renovado com sucesso!\n");

							sleep(3);
							break;
						case 1:
							DevolverLivro(usuario, cod);

							printf("\nLivro ");
							printf(TC_RED);
							printf("%s ", titulo);
							printf(TC_RST);
							printf("devolvido com sucesso!\n");

							sleep(3);
							break;
					}
				printf("\nProcurando por mais livros fora do prazo...\n");
				sleep(3);
				return 0;
				}
			}
		}
	}
	fclose(fleitura);
	return 1;
}

char ChecaAluguel (User *usuario, unsigned long long cod) {
	char linha[80] = {0};
	char cmp[10] = {0};
	char *ptr;
	int cont = 0;
	FILE * fleitura = fopen("Dados/aluguel.txt", "r");

	if (!fleitura) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(fleitura)) {
		memset(linha, 0, 80);
		fgets(linha, 80, fleitura);

		ptr = strtok(linha, ":");

		if (cont == 5)
			return 2;
		if (ptr == NULL)
			break;
		if (strcmp(ptr, usuario->login) == 0) {
			ptr = strtok(NULL, ":");
			cont ++;
			NumToStr(cod, cmp, 10);

			if (strcmp(cmp, ptr) == 0) {
				fclose(fleitura);
				return 0; 
			}
		}
	}
	fclose(fleitura);
	return 1;
}

#endif
