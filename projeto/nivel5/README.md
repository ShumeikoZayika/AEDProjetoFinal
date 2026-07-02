# Nível 5 — Interface gráfica demonstrativa (desktop nativa, raylib)

Aplicação de **janela nativa** em C++ que desenha o grafo de conhecimento. Sem
browser, sem HTML, sem servidor. O motor (Níveis 1–4) calcula tudo; a janela só
desenha e reage ao rato, por isso o que se vê reflete cálculos reais do sistema.

## Dependências (macOS)

```bash
brew install sqlite raylib pkg-config
```

(O Makefile usa `pkg-config` para localizar o SQLite e o raylib.)

## Como correr

```bash
make           # compila
make run       # ou ./cti_graph  -> abre a janela gráfica
make menu      # menu de texto (operações da Fase 4)
make demo      # demonstração de texto não interativa
make test      # bateria de testes
```

A interface gráfica controla **todas** as operações (não só visualização): criar
nós e relações, guardar/recarregar a base de dados, filtrar, consultar vizinhos,
calcular caminhos e ver rankings — tudo dentro da janela, com validação.

### Visualização e consulta

| Ação | Resultado |
|------|-----------|
| Arrastar um nó | reposiciona-o (layout force-directed) |
| Arrastar o fundo | desloca a vista (pan) |
| Roda do rato | zoom centrado no cursor |
| Clique esquerdo num nó | seleciona-o; detalhes + vizinhos (entrada/saída); escurece o resto |
| Clique direito noutro nó | desenha o **caminho BFS** (origem = nó selecionado) |
| Clicar na legenda | liga/desliga a visibilidade de cada tipo |
| `ESPAÇO` / `R` / `0` | layout on-off / limpar seleção / repor vista |

### Operações (botões no painel + atalhos)

| Botão / tecla | Operação | Camada |
|---------------|----------|--------|
| **Procurar por id** | escreve um id + `Enter` → `getNode` (mapa, O(log V)); seleciona e centra o nó | grafo (Fase 1) |
| **Novo nó** (`N`) | formulário: id, label, tipo → `createNode` (validado) | serviço (Fase 4) |
| **Nova relação** (`E`) | formulário: origem, destino, relação → `createEdge` (validado) | serviço (Fase 4) |
| **Apagar nó** (`Del`) | remove o nó selecionado e as relações incidentes → `deleteNode` | serviço (Fase 4) |
| **Apagar relação** | formulário: origem, destino, relação → `deleteEdge` | serviço (Fase 4) |
| **Guardar BD** (`G`) | grava o grafo em SQLite → `save` | persistência (Fase 2) |
| **Recarregar BD** | reconstrói o grafo da BD → `reload` | persistência (Fase 2) |
| **Travessia BFS / DFS** | a partir do nó selecionado, numera os nós pela ordem de visita e lista no painel → `bfs`/`dfs` | algoritmos (Fase 3) |
| **Duplicados / resolução** | deteta e realça (anel magenta) grupos de nós que são a mesma entidade → `findPotentialDuplicates` | algoritmos (Fase 3) |
| **Consultas analíticas** | ao selecionar um malware, o painel mostra "atores que usam" e "indicadores que apontam" → `actorsUsingMalware`/`indicatorsForThreat` | algoritmos (Fase 3) |
| **Estatísticas / lista por tipo** | sem seleção, o painel mostra contagem por tipo; clique direito na legenda lista os nós desse tipo → `listNodesByType` | serviço (Fase 4) |
| **Mais provável** | escolhe uma origem e um tipo (ator, malware, …); calcula a entidade mais provável desse tipo por `score = PageRank / distância (BFS)`, com ranking justificado | inferência (Fase 3) |
| **Cenário (demo narrativa)** | percorre os 4 passos: indicador → malware → ator → caminho BFS, com texto no painel | demonstração (Fase 5) |
| **Ranking: PageRank/Grau** | alterna o ranking apresentado | algoritmos (Fase 3) |

Formulários (com rato ou teclado, sem decorar ids):

- **Criar nó**: escreve `id` e `label`; o **tipo** escolhe-se com as setas `<` `>`
  (ou `↑`/`↓`).
- **Criar relação**: origem, destino e tipo de relação escolhem-se todos por
  **seleção** (setas `<` `>` ou clique) a partir das listas existentes — não é
  preciso escrever nada. Pré-preenche a origem com o nó selecionado e o destino
  com o último nó marcado com clique direito.
- **Apagar relação** usa o mesmo formulário por seleção (botão fica "Apagar").
- `TAB` muda de campo, `ENTER`/botão confirma, `ESC`/**Cancelar** fecha o formulário
  (o `ESC` já não fecha a aplicação).

As mensagens de sucesso (verde) e erro (vermelho) da validação aparecem no painel
(ex.: id duplicado, relação inválida pela matriz, nó inexistente).

## Porque reflete cálculos reais (critério da Fase 5)

- **Raio do nó** = PageRank (`Algorithms::pageRank`), normalizado.
- **Cor do nó** = tipo de entidade.
- **Detalhes do nó** = grau de entrada/saída (`Graph::inDegree/outDegree`) e
  vizinhos das listas de adjacência (saída e inversa).
- **Caminho destacado** = `Algorithms::shortestPath` (BFS) calculado em C++.

Nada é estático: todos os valores vêm dos algoritmos implementados.

## Tipo de letra

A interface carrega uma fonte TTF do sistema (Arial/Helvetica/SF no macOS, com
fallback para DejaVu/Segoe) num atlas de alta resolução com filtragem suave, em
vez da fonte bitmap base do raylib — os nomes ficam nítidos a qualquer zoom. Se
nenhuma fonte for encontrada, recai automaticamente na fonte por omissão.

## Arquitetura

A GUI (`src/gui.*`) é apenas a camada de apresentação; toda a lógica continua em
`graph`, `algorithms`, `database` e na camada de serviços `service` (Nível 4). O
menu de texto (`--menu`) e a GUI partilham o mesmo motor.
