#ifndef _STRUCTS_
#define _STRUCTS_

typedef struct {
	char login[30];
	char senha[41];
	char admin;
} User;

typedef struct {
	char nome[51];
	unsigned long long cod;
	unsigned long long livros_escritos[100];
} Autor;

typedef struct {
	char titulo[51];
	unsigned long long codigo;
	unsigned long long autor;
	unsigned short quantidade;
	unsigned short alugado;
	double preco;
	unsigned long long proximo;
} Livro;

#endif
