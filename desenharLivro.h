#ifndef  _DESENHAR_LIVRO_
#define _DESENHAR_LIVRO_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "listaStr.h"
#include "term.h"

//-------------------FUNCIONALIDADES--------------------

void ChangeChar(char* c, char val, char change);

void HoldText (int _opc);
void LoadText ();
void UnsaveText (char _opc);
void SaveText (char _opc);

void DrawBegin ();
void DrawTextLeft (char* c, char* cor);
void DrawTextRight (char* c, char* cor);
void DrawTextSpace (char _opc);
void DrawEnd ();
void DrawTopoLivro ();
void DrawBottomLivro ();


void AnimLivro (char check);

listaStr* lista1 = NULL;
listaStr* lista2 = NULL;
listaStr* lst1 = NULL;
listaStr* lst2 = NULL;
int high = 14;
char begin = 0;
char manterStr = 0;

//-----------------------FUNÇÕES------------------------

void ChangeChar (char* c, char val, char change) {
	while (*c) {
		if (*c == val)
			*c = change;
		c++;
	}
}

void freadText(FILE* file, char* str, const char* end, int size) {
	int _s = 0;
	char c;

	while(_s++ < size && !feof(file)) {
		c = fgetc(file);

		if (c == '\n') {
			*str = 0;
			return;
		}
		for (int i = 0; !end[i]; i++) {
			if (end[i] == c) {
				*str = 0;
				return;
			}
		}
		*str = c;
		str++;
	}
}

void HoldText (int _opc) {
	if(_opc == 'L' || _opc == 'l')
		_opc = 2;
	if(_opc == 'R' || _opc == 'r')
		_opc = 3;
	if(_opc < 1 || _opc > 3)
		_opc = 1;
	manterStr = _opc;
}

void LoadText () {
	if (lst1) {
		for (str_no* no = lst1->ini; no != lst1->fim; no = no->prox)
			PushBackStr(lista1, no->str, no->cor);
	}
	if (lst2) {
		for (str_no* no = lst2->ini; no != lst2->fim; no = no->prox)
			PushBackStr(lista2, no->str, no->cor);
	}
}

void UnsaveText (char _opc) {
	switch (_opc) {
		case 1:
			ClearListStr(lst1);
			ClearListStr(lst2);
			break;
		case 2:
		case 'L':
		case 'l':
			ClearListStr(lst1);
			break;
		case 3:
		case 'R':
		case 'r':
			ClearListStr(lst2);
			break;
	}
}

void SaveText (char _opc) {
	switch (_opc) {
		case 2:
		case 'L':
		case 'l':
			lst1 = InitListaStr(lst1);
			ClearListStr(lst1);

			for (str_no* no = lista1->ini; no != lista1->fim; no = no->prox)
				PushBackStr(lst1, no->str, no->cor);
			break;
		case 3:
		case 'R':
		case 'r':
			lst2 = InitListaStr(lst2);
			ClearListStr(lst2);
			for (str_no* no = lista2->ini; no != lista2->fim; no = no->prox)
				PushBackStr(lst2, no->str, no->cor);
			break;
		default:
			lst1 = InitListaStr(lst1);
			lst2 = InitListaStr(lst2);
			ClearListStr(lst1);
			ClearListStr(lst2);

			for (str_no* no = lista1->ini; no != lista1->fim; no = no->prox)
				PushBackStr(lst1, no->str, no->cor);
			for (str_no* no = lista2->ini; no != lista2->fim; no = no->prox)
				PushBackStr(lst2, no->str, no->cor);
			break;
	}
}

void DrawBegin () {
	lista1 = InitListaStr(lista1);
	lista2 = InitListaStr(lista2);
	if (manterStr != 1) {
		if (manterStr == 3 || !manterStr)
			ClearListStr(lista1);
		if (manterStr == 2 || !manterStr)
			ClearListStr(lista2);
	}
	begin = 1;
}

void DrawTextLeft (char* c, char* cor) {
	if (!begin || !lista1)
		return;
	PushBackStr(lista1, c, cor);
}

void DrawTextRight (char* c, char* cor) {
	if (!begin || !lista2)
		return;
	PushBackStr(lista2, c, cor);
}

void DrawTextLine (char* c, char* cor) {
	int _size = 0;
	int meio;
	
	if (c) {
		int sub = 0;
		while (c[_size]){
			if(c[_size++] == -30) sub += 2;
		}
		_size -= sub;
		ChangeChar(c, ' ', '_');
	}
	
	meio = _size / 2;
	printf("\033[30;47m║ ");
	for (int i = 10 - meio; i>0; i--)
		printf("_");
	if (cor)
		printf(cor);

	if(_size){
		printf("%s", c);
	}
	
	printf("\033[30;47m");
	meio = _size - meio;

	for (int i = 10 - meio; i>0; i--)
		printf("_");
	printf(" ║");
	
}

void DrawTextSpace (char _opc) {
	switch (_opc) {
		case 2:
		case 'l':
		case 'L':
			PushBackStr(lista1, NULL, NULL);
			break;
		case 3:
		case 'r':
		case 'R':
			PushBackStr(lista2, NULL, NULL);
			break;
		default:
			PushBackStr(lista1, NULL, NULL);
			PushBackStr(lista2, NULL, NULL);
			break;
	}
}

void DrawEnd () {
	SetCursorPosition(1,1);
	DrawTopoLivro();
	str_no* no1 = lista1->ini;
	str_no* no2 = lista2->ini;
	
	for (int i = 0; i<high; i++) {
		printf("\n");

		if (no1 != lista1->fim) {
			DrawTextLine(no1->str, no1->cor);
			no1 = no1->prox;
		}
		else
			DrawTextLine(NULL, NULL);
		printf(" ");

		if (no2 != lista2->fim) {
			DrawTextLine(no2->str, no2->cor);
			no2 = no2->prox;
		}
		else
			DrawTextLine(NULL, NULL);
	}
	DrawBottomLivro();

	if (manterStr != 1) {
		if (manterStr == 3 || !manterStr)
			ClearListStr(lista1);
		if (manterStr == 2 || !manterStr)
			ClearListStr(lista2);
	}
	begin = 0;
	printf("\x1B[0m");
}

void DrawTopoLivro () {
	printf("\033[30;47m%49s", "");
	printf("\n%49s\n%49s\n", "", "");
	printf("\033[30;47m  ╔═══════════════╗%11s╔═══════════════╗  ", "");
	printf("\n╔═╝%15s╚═══╗   ╔═══╝%15s╚═╗", "", "");
	printf("\n║  __________________ ╚╦═╦╝ __________________  ║");
	printf("\x1B[0m");
}

void DrawBottomLivro () {
	printf("\033[30;47m\n║ ╔═══════════════╗    ║ ║    ╔═══════════════╗ ║");
	printf("\n╠═╝ _____________ ╚══╗ ║ ║ ╔══╝ _____________ ╚═╣");
	printf("\n╚╗ _________________ ╚╗║ ║╔╝ _________________ ╔╝");
	printf("\n ╚╗ _________________ ╚╩═╩╝ _________________ ╔╝ ");
	printf("\n  ╚═════════════════╗ \\   / ╔═════════════════╝  ");
	printf("\n%20s╚═══════╝%20s", "", "");
	printf("\x1B[0m");
}

void AnimLivro (char check) {
	SetCursorPosition(1,1);
	char linha[141] = {0};
	int cont = 0;
	int i = 0;
	int verificador;
	FILE* fleitura;

	if (check == 'E' || check == 'e') {
		fleitura = fopen("Animacoes/Textos_Anin/livro_pg_esq_anin.txt", "r");
	} 
	if (check == 'd' || check == 'D') {
		fleitura = fopen("Animacoes/Textos_Anin/livro_pg_dir_anin.txt", "r");
	}
	if (check == 'A' || check == 'a') {
		fleitura = fopen("Animacoes/Textos_Anin/livro_abre_anin.txt", "r");
	} 
	if (check == 'F' || check == 'f') {
		fleitura = fopen("Animacoes/Textos_Anin/livro_fecha_anin.txt", "r");
	}
	if (!fleitura) {
		printf("Erro na abertura do arquivo\n");
		exit(1);
	}
	while (!feof(fleitura)) {
		i = 0;
		verificador = 0;
		memset(linha, 0, 140);
		fgets(linha, 140, fleitura);

		if (cont == 4 && check == 'A')
			break;
		if (cont == 5 && check == 'E')
			break;
		if (cont == 6)
			break;
		if (linha[i] == 'F') {
			cont++;
			if (cont == 1 && (check == 'A' || check == 'a'))
				sleep(3);
			if (cont == 5  && (check == 'F' || check == 'f'))
				usleep(200000);
			else
				usleep(300000);
			SetCursorPosition(1,1);
		}
		else {
			for (i = 0; i < strlen(linha); i++) {
				if (linha[i] == 'S' && linha[i+1] == 'A') {
					printf(TC_RED);
					printf("SAIR");
					i = i + 3;
					verificador = 0;
					continue;
				}
				if (!verificador) {
					printf("\033[30;47m");
					verificador++;
				}
				if ((linha[i] <= 'Z'&& linha[i] >= 'A') || (linha[i] <= 'Z'&& linha[i] >= 'A') || linha[i] == '!') {
					printf(TC_GRN);
					verificador = 0;
				}
				printf("%c", linha[i]);
			}
			printf(TC_RST);
		}
	}
	fclose(fleitura);
}

#endif
