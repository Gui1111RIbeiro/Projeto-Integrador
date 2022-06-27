#ifndef _LISTA_LIVRO_
#define _LISTA_LIVRO_

#include <stdio.h>
#include <stdlib.h>

#include "structs.h"

typedef struct NodeLivro {
	Livro livro;
	struct NodeLivro *proximo;
	struct NodeLivro *anterior;
} t_noL;

typedef struct {
	size_t size;
	t_noL *inicio;
	t_noL *fim;
} listaLivro;

//-------------------FUNCIONALIDADES--------------------

listaLivro* InitList (listaLivro* lista);
void PushBack (listaLivro* lista, Livro livro);
void PushFront (listaLivro* lista, Livro livro);
void PopBack (listaLivro* lista);
void PopFront (listaLivro* lista);
listaLivro* ClearList (listaLivro* lista);

//-----------------------FUNÇÕES------------------------

listaLivro* InitList (listaLivro* lista) {
	if (lista != NULL)
		return lista;
	lista = (listaLivro*)malloc(sizeof(listaLivro));
	lista->size = 0;
	lista->inicio = (t_noL*)malloc(sizeof(t_noL));
	lista->fim = lista->inicio;
	lista->fim->proximo = NULL;
	lista->fim->anterior = NULL;

	return lista;
}

void PushBack (listaLivro* lista, Livro livro) {
	lista = InitList(lista);
	lista->fim->livro = livro;
	lista->fim->proximo = (t_noL*)malloc(sizeof(t_noL));

	if (!lista->fim->proximo)
		return;
	lista->fim->proximo->anterior = lista->fim;
	lista->fim = lista->fim->proximo;
	lista->fim->proximo = NULL;
	lista->size++;
}

void PushFront (listaLivro* lista, Livro livro) {
	lista = InitList(lista);

	t_noL* node = lista->inicio;

	lista->inicio = (t_noL*)malloc(sizeof(t_noL));
	lista->inicio->livro = livro;
	lista->inicio->proximo = node;
	node->anterior = lista->inicio;
	lista->inicio->anterior = NULL;
	lista->size++;
}

void PopBack (listaLivro* lista) {
	if (!lista->size)
		return;
	lista->fim->proximo = NULL;
	lista->fim = lista->fim->anterior;
	lista->fim->proximo = NULL;
	lista->size--;
}

void PopFront (listaLivro* lista) {
	if (!lista->size)
		return;
	t_noL* node = lista->inicio->proximo;

	if (!node)
		return;
	free(lista->inicio);
	node->anterior = NULL;
	lista->inicio = node;
	lista->size--;
}

listaLivro* ClearList (listaLivro* lista) {
	lista = InitList(lista);

	while (lista->fim->anterior) {
		lista->fim = lista->fim->anterior;
		free(lista->fim->proximo);
	}
	lista->size = 0;
	lista->fim->proximo = NULL;

	return lista;
}

void DeleteList (listaLivro* lista){
	if (!lista)
		return;
	lista = ClearList(lista);
	free(lista->inicio);
	free(lista);
	lista = NULL;
}

#endif
