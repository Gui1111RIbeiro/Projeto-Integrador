#ifndef _LISTA_STR_
#define _LISTA_STR_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct String{
	struct String* prox;
	char str[200];
	char cor[30];
}str_no;

typedef struct{
	unsigned int size;
	str_no* ini;
	str_no* fim;
}listaStr;

//-------------------FUNCIONALIDADES--------------------

listaStr* InitListaStr (listaStr* lista);
char PushBackStr (listaStr* lista, char* c, char* cor);
listaStr* ClearListStr (listaStr* lista);

//-----------------------FUNÇÕES------------------------

listaStr* InitListaStr (listaStr* lista) {
	if (lista)
		return lista;
	lista = (listaStr*)malloc(sizeof(listaStr));
	if (!lista)
		return NULL;
	lista->size = 0;
	lista->ini = (str_no*)malloc(sizeof(str_no));
	if (!lista->ini) {
		free(lista);
		lista = NULL;
		return NULL;
	}
	lista->ini->prox = NULL;
	lista->fim = lista->ini;
	return lista; 
}

char PushBackStr (listaStr* lista, char* c, char* cor) {
	lista = InitListaStr(lista);
	if (!lista->fim)
		return 0;
	memset(lista->fim->str, 0, 200);

	if (c) {
		int size = strlen(c);
		memcpy(lista->fim->str, c, size);
	}
	memset(lista->fim->cor, 0, 30);

	if (cor) {
		int size = strlen(cor);
		memcpy(lista->fim->cor, cor, size);
	}
	lista->fim->prox = (str_no*)malloc(sizeof(str_no));
	lista->fim = lista->fim->prox ? lista->fim->prox : NULL;

	if (lista->fim)
		lista->fim->prox = NULL;
	lista->size++;
	return 1;
}

listaStr* ClearListStr (listaStr* lista) {
	if (!lista)
		return NULL;
	str_no* no = lista->ini;
	str_no* aux = NULL;

	while (no != lista->fim) {
		aux = no->prox;
		free(no);
		no = aux;
	}
	if (no)
		free(no);
	lista->ini = (str_no*)malloc(sizeof(str_no));
	lista->fim = lista->ini;
	lista->size = 0;
	return lista;
}

#endif
