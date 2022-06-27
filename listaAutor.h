#ifndef _LISTA_AUTOR_
#define _LISTA_AUTOR_

#include <stdio.h>
#include <stdlib.h>

#include "structs.h"

typedef struct NodeAutor {
	Autor autor;
	struct NodeAutor *proximo;
	struct NodeAutor *anterior;
} t_noA;

typedef struct {
	size_t size;
	t_noA *inicio;
	t_noA *fim;
} listaAutor;

//-------------------FUNCIONALIDADES--------------------

listaAutor* InitListA (listaAutor*);
void PushBackA (listaAutor* lista, Autor autor);
void PushFrontA (listaAutor* lista, Autor autor);
void PopBackA (listaAutor* lista);
void PopFrontA (listaAutor* lista);
listaAutor* ClearListA (listaAutor* lista);

//-----------------------FUNÇÕES------------------------

listaAutor* InitListA (listaAutor* lista) {
	if (lista != NULL)
		return lista;
	lista = (listaAutor*)malloc(sizeof(listaAutor));
	lista->inicio = (t_noA*)malloc(sizeof(t_noA));

	lista->size = 0;
	lista->fim = lista->inicio;
	lista->fim->proximo = NULL;
	lista->fim->anterior = NULL;

	return lista;
}

void PushBackA (listaAutor* lista, Autor autor) {
	lista = InitListA(lista);
	lista->fim->autor = autor;
	lista->fim->proximo = (t_noA*)malloc(sizeof(t_noA));

	if (!lista->fim->proximo)
		return;
	lista->fim->proximo->anterior = lista->fim;
	lista->fim = lista->fim->proximo;
	lista->fim->proximo = NULL;
	lista->size++;
}

void PushFrontA (listaAutor* lista, Autor autor) {
	lista = InitListA(lista);

	t_noA* node = lista->inicio;

	lista->inicio = (t_noA*)malloc(sizeof(t_noA));
	lista->inicio->autor = autor;
	lista->inicio->proximo = node;
	node->anterior = lista->inicio;
	lista->inicio->anterior = NULL;
	lista->size++;
}

void PopBackA (listaAutor* lista) {
	if (!lista->size)
		return;
	lista->fim->proximo = NULL;
	lista->fim = lista->fim->anterior;
	lista->fim->proximo = NULL;
	lista->size--;
}

void PopFrontA (listaAutor* lista) {
	if (!lista->size)
		return;
	t_noA* node = lista->inicio->proximo;

	if (!node)
		return;
	free(lista->inicio);
	node->anterior = NULL;
	lista->inicio = node;
	lista->size--;
}

listaAutor* ClearListA (listaAutor* lista) {
	lista = InitListA(lista);

	while (lista->fim->anterior) {
		lista->fim = lista->fim->anterior;
		free(lista->fim->proximo);
	}
	lista->size = 0;
	lista->fim->proximo = NULL;

	return lista;
}

void DeleteListA (listaAutor* lista){
	if (!lista)
		return;
	ClearListA(lista);
	free(lista->inicio);
	free(lista);
	lista = NULL;
}

#endif
