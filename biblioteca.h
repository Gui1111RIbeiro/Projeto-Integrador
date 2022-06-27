#ifndef _BIBLIOTECA_
#define _BIBLIOTECA_

#include <stdio.h>
#include <stdlib.h>

#include "aluguel.h"
#include "../Animacoes/term.h"
#include "../Animacoes/desenharLivro.h"
#include "../Listas/listaAutor.h"
#include "../Listas/listaLivro.h"
#include "../Listas/structs.h"

#define ull unsigned long long

//-------------------FUNCIONALIDADES--------------------

char NameHas (char*, char*);
void ShowBiblioteca (listaLivro*, int pagina, int *totalPagina, int livrosPagina);
Livro BuscarLivroCod (ull cod);
void Buscar_Livro (listaLivro*, char* nome, char quant);
int Add_Livro (Livro* livro);
void BuscarAutorCod (ull cod, Autor* autor);
void BuscarAutor (listaAutor* lista, char* nome, size_t quant);
void Add_LivroAutor (ull codAutor, ull codLivro);

//-----------------------FUNÇÕES------------------------

char NameHas (char* buff1, char* buff2) {
	size_t i = 0;
	size_t j = 0;
	size_t pos = i;
	char resp = 0;

	while (buff1[i] && buff2) {
		if (buff1[i++] != buff2[0]) {
			j = 0;
			continue;
		}
		resp = 1;
		pos = i;
		j = 1;

		while (buff1[i] && buff2[j]) {
			if (buff1[i++] != buff2[j++]) {
				j = 0;
				i = pos;
				resp = 0;
				break;
			}
		}
		resp = !buff2[j];
		i = pos;

		if (resp)
			break;
	}
	return resp;
}

void ShowBiblioteca (listaLivro* lista, int pagina, int *totalPagina, int livrosPagina) {
	FILE* file = fopen("Dados/livros.bin", "rb");
	if(!file) return;
		
	if(!lista) InitList(lista);

	char cont = 0;
	ull cod = 0;
	while(!cod){
		if(feof(file) || cont == 27){
			fclose(file);
			return;
		}
		cont++;
		fread(&cod, sizeof(ull), 1, file);
	}

	ull quant;
	fpos_t pos;
	fseek(file, 27*sizeof(ull), SEEK_SET);
	fread(&quant, sizeof(ull), 1, file);
	fgetpos(file, &pos);

	if(quant < (pagina-1)*livrosPagina) return;

	*totalPagina = quant / livrosPagina;
	if(quant % livrosPagina) *totalPagina += 1;

	Livro livro;

	size_t contL = 0;
	size_t pag = 1;
	while(1){
		fsetpos(file, &pos);
		fseek(file, sizeof(Livro)*(cod-1), SEEK_CUR);
		
		if(feof(file)) break;

		fread(&livro, sizeof(Livro), 1, file);
		if(pagina == pag) PushBack(lista, livro);
		cod = livro.proximo;
		
		contL++;
		if(contL >= livrosPagina) {
			contL = 0;
			pag++;
			if(pag > pagina) break;
		}
		
		if(!cod){
			rewind(file);
			fseek(file, sizeof(ull)*cont, SEEK_CUR);
			while(!cod){
				if(feof(file) || cont == 27){
					fclose(file);
					return;
				}
				cont++;
				fread(&cod, sizeof(ull), 1, file);
			}
		}
	}
	fclose(file);
}

Livro BuscarLivroCod (ull cod) {
	Livro livro;
	livro.codigo = 0;
	FILE* file = fopen("Dados/livros.bin", "rb");

	if (!file) return livro;

	
	fseek(file, 27*sizeof(ull), SEEK_SET);
	if(feof(file)) return livro;
	
	ull quant = 0;
	fread(&quant, sizeof(ull), 1, file);

	if (feof(file) || ferror(file) || quant < cod) {
		fclose(file);
		return livro;
	}
	fseek(file, sizeof(Livro)*(cod-1), SEEK_CUR);
	fread(&livro, sizeof(Livro), 1, file);
	fclose(file);
	return livro;
}

void Buscar_Livro (listaLivro* lista, char* nome, char quantL) {
	Livro livro;
	livro.titulo[0] = 0;
	livro.codigo = 0;
	if(!quantL) quantL = 100;

	if(!nome) return;
	Upper_Case(nome);

	FILE* file = fopen("Dados/livros.bin", "rb");

	if (!file) return;

	fseek(file, 0, SEEK_END);

	if(ftell(file) < 28*sizeof(ull)) {
		fclose(file);
		return;
	}
	
	char tam = 0;
	if(nome[0] >= 'A' && nome[0] <= 'Z'){
		tam = nome[0] - 'A';
	}else{
		tam = 'Z' - 'A' + 1;
	}
	fseek(file, tam*sizeof(ull), SEEK_SET);
	
	ull cod = 0;
	fread(&cod, sizeof(ull), 1, file);

	if (feof(file) || ferror(file) || !cod) {
		fclose(file);
		return;
	}
	if (!lista) lista = InitList(lista);
	
	fseek(file, 27*sizeof(ull), SEEK_SET);
	
	ull quant = 0;
	fread(&quant, sizeof(ull), 1, file);
	fpos_t pos;
	fgetpos(file, &pos);

	char encontrou = 0;
	
	while (1) {
		if(feof(file) || quant < cod || ferror(file)){
			livro.codigo = 0;
			break;
		}
		fsetpos(file, &pos);
		fseek(file, sizeof(Livro)*(cod-1), SEEK_CUR);
		fread(&livro, sizeof(Livro), 1, file);

		char igual = NameHas(livro.titulo, nome);
		char maior = strcmp(livro.titulo, nome);

		cod = livro.proximo;
		
		if (!igual && encontrou) break;
		if(maior == 1) break;
		if(!igual) continue;

		encontrou = 1;
		PushBack(lista, livro);
		quantL--;
		if(!quantL) break;
	}
	fclose(file);
	return;
}

int Add_Livro (Livro* livro) {
	
	Upper_Case(livro->titulo);

	if(!livro->titulo[0]) return -1;

	FILE* file = fopen("Dados/livros.bin", "rb+");

	if (!file) return 0;

	fseek(file, SEEK_SET, SEEK_END);

	if(ftell(file) < 28*sizeof(ull)){
		rewind(file);
		ull none = 0;
		for(int i = 0; i<28; i++)
			fwrite(&none, sizeof(ull), 1, file);
		rewind(file);
	}
	
	char tam = 0;
	if(livro->titulo[0] >= 'A' && livro->titulo[0] <= 'Z'){
		tam = livro->titulo[0] - 'A';
	}else{
		tam = 'Z' - 'A' + 1;
	}
	fseek(file, tam*sizeof(ull), SEEK_SET);
	
	ull cod = 0;
	fread(&cod, sizeof(ull), 1, file);
	
	fseek(file, 27*sizeof(ull), SEEK_SET);

	ull quant = 0;
	fread(&quant, sizeof(ull), 1, file);
	
	++quant;
	livro->codigo = quant;
	livro->proximo = 0;

	fpos_t pos;
	fgetpos(file, &pos);
	
	Livro aux;
	aux.codigo = 0;
	ull codAnterior = cod;
	while(cod){
		if(feof(file) || cod < quant){
			break;
		}

		if(ferror(file)){
			fclose(file);
			return -2;
		}
		
		fsetpos(file, &pos);
		fseek(file, sizeof(Livro)*(cod-1), SEEK_CUR);
		fread(&aux, sizeof(Livro), 1, file);


		char comp = strcmp(livro->titulo, aux.titulo);
		if(comp == -1 || !comp) break;
		codAnterior = cod;
		cod = aux.proximo;
	}

	if(aux.codigo){
		livro->proximo = aux.codigo;
		if(cod != codAnterior){
			fsetpos(file, &pos);
			fseek(file, sizeof(Livro)*(codAnterior-1), SEEK_CUR);
			fpos_t novaPos;
			fgetpos(file, &novaPos);
			fread(&aux, sizeof(Livro), 1, file);
			aux.proximo = livro->codigo;
			fsetpos(file, &novaPos);
			fwrite(&aux, sizeof(Livro), 1, file);
		}
	}

	if(cod == codAnterior || !aux.codigo){
		fseek(file, tam*sizeof(ull), SEEK_SET);
		fwrite(&livro->codigo, sizeof(ull), 1, file);
	}

	fseek(file, 27*sizeof(ull), SEEK_SET);
	fwrite(&quant, sizeof(ull), 1, file);

	freopen("Dados/livros.bin", "ab", file);
	livro->alugado = 0;
	livro->quantidade = 1;
	fwrite(livro, sizeof(Livro), 1, file);

	fclose(file);
	return 1;
}

void BuscarAutor (listaAutor* lista, char* nome, size_t quant) {
	Autor autor;
	size_t tam = !quant || quant > 100 ? 100 : quant;
	FILE* file = fopen("Dados/autores.bin", "rb");

	Upper_Case(nome);

	if (!file) {
		return;
	}
	ull quantA = 0;
	fread(&quantA, sizeof(ull), 1, file);

	while (fread(&autor, sizeof(Autor), 1, file) != EOF) {
		if (feof(file))
			break;
		if (NameHas(autor.nome, nome)) {
			PushBackA(lista, autor);
			if (!--tam)
				break;
		}
	}
	fclose(file);
	return;
}

void BuscarAutorCod (ull cod, Autor* autor) {
	if(!autor) return; 
	Autor aux;
	FILE* file = fopen("Dados/autores.bin", "rb");

	if (!file) return;
	
	
	ull quantA = 0;
	fread(&quantA, sizeof(ull), 1, file);

	while (!feof(file)) {
		fread(&aux, sizeof(Autor), 1, file);

		if (aux.cod == cod) {
			*autor = aux;
			fclose(file);
			return;
		}
	}
	return;
}

Autor Add_Autor (Autor autor) {
	size_t cod = 0;
	FILE* file = fopen("Dados/autores.bin", "rb+");
	autor.cod = 0;
	if (!file) {
		return autor;
	}
	memset(&autor.livros_escritos, 0, 100*sizeof(ull));
	Upper_Case(autor.nome);
	
	fread(&cod, sizeof(ull), 1, file);
	autor.cod = ++cod;

	rewind(file);
	fwrite(&cod, sizeof(ull), 1, file);
	
	freopen("Dados/autores.bin", "ab", file);
	fwrite(&autor, sizeof(Autor), 1, file);

	fclose(file);
	return autor;
}

void Add_LivroAutor (ull codAutor, ull codLivro) {
	FILE* file = fopen("Dados/autores.bin", "rb+");

	if (!file) {
		return;
	}
	ull quantA= 0;
	fread(&quantA, sizeof(ull), 1, file);
	Autor autor;
	fpos_t pos;

	while (!feof(file)) {
		fgetpos(file, &pos);
		fread(&autor, sizeof(Autor), 1, file);
		if(autor.cod != codAutor) continue;
		
		fsetpos(file, &pos);

		for (int i = 0; i<100; i++) {
			if (autor.livros_escritos[i]) continue;
			autor.livros_escritos[i] = codLivro;
			break;
		}
		fwrite(&autor, sizeof(Autor), 1, file);
		break;
	}
	fclose(file);
}

char AttLivro(Livro livro){
	FILE* file = fopen("Dados/livros.bin", "rb+");
	if(!file) return -1;

	fseek(file, 27*sizeof(ull), SEEK_SET);

	if(feof(file)) return -1;
	
	ull quant = 0;
	fread(&quant, sizeof(ull), 1, file);
	
	if(!quant){
		fclose(file);
		return 1;
	}
	
	if(quant < livro.codigo){
		fclose(file);
		return 2;
	}
	
	fseek(file, (livro.codigo - 1)*sizeof(Livro), SEEK_CUR);
	
	if(feof(file)){
		fclose(file);
		return 3;
	}
	
	fwrite(&livro, sizeof(Livro), 1, file);
	fclose(file);
	return 0;
}

#endif
