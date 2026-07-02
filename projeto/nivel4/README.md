# Nível 4 — Acesso local / camada de serviços

Transforma o projeto numa aplicação organizada e reutilizável, com separação
clara entre **lógica** (grafo, persistência, algoritmos), **camada de serviços**
(`src/service.*`) e **interface** (menu local em `main.cpp`).

## Arquitetura (módulos)

| Módulo | Ficheiro | Responsabilidade |
|--------|----------|------------------|
| Tipos / nós / arestas | `src/types.h`, `src/node.h`, `src/edge.h` | Tipos abstratos de dados |
| Grafo | `src/graph.*` | Listas de adjacência (saída + inversa), inserção, validação, consultas |
| Persistência | `src/database.*` | SQLite: gravar/carregar, pesquisas |
| Algoritmos | `src/algorithms.*` | BFS, DFS, caminho mais curto, grau, PageRank, resolução de entidades |
| **Serviço** | `src/service.*` | Operações validadas expostas à interface (CRUD + consultas + stats) |
| Interface | `main.cpp` | Menu local (REPL) que só chama a camada de serviços |
| Testes | `src/tests.cpp` | Unitários + integração da camada de serviços |

A interface **nunca** toca diretamente no grafo: passa sempre pelo `Service`,
que valida a entrada e devolve `OpResult { ok, message }`.

## Como executar

```bash
make            # compila
./cti_graph     # menu interativo
make demo       # demonstração automática (não interativa) de todas as operações
make test       # bateria de testes (unitários + integração)
```

## Comandos do menu (operações expostas)

| Comando | Operação | Equivalente a endpoint |
|---------|----------|------------------------|
| `stats` | estatísticas gerais | `GET /stats` |
| `nodes <tipo>` | listar nós por tipo | `GET /nodes?type=` |
| `node <id>` | obter nó por identificador | `GET /node/{id}` |
| `addnode <id> <tipo> <label>` | criar nó | `POST /node` |
| `addedge <orig> <dest> <rel>` | criar relação | `POST /edge` |
| `neighbours <id> [out\|in\|both]` | listar vizinhos | `GET /neighbours/{id}` |
| `path <orig> <dest>` | caminho mais curto (BFS) | `GET /path?src=&dst=` |
| `ranking` | entidades mais relevantes (PageRank) | `GET /ranking` |
| `degree` | centralidade por grau | `GET /degree` |
| `save` / `reload` | persistência | `POST /save`, `POST /reload` |

## Validação e tratamento de erros

A camada de serviços rejeita e explica, entre outros:

- nó com `id` duplicado ou tipo de entidade inválido;
- relação que viola a matriz de relações permitidas;
- relação com origem/destino inexistente;
- consulta a nó inexistente;
- direção de vizinhança inválida;
- caminho inexistente entre dois nós.

Exemplo (de `make demo`):

```
> addedge wannacry evilcorp targets
  ERRO: Relação inválida segundo a matriz de relações permitidas:
        wannacry --targets--> evilcorp.
> path apt29 lazarus
  ERRO: Não existe caminho entre 'apt29' e 'lazarus'.
```
