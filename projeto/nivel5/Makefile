# Nível 5 — interface gráfica nativa (raylib) + menu de texto
#
# Dependências (macOS / Homebrew):
#   brew install sqlite raylib pkg-config
# Usa pkg-config para encontrar sqlite3 e raylib (à prova de versões).

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 $(shell pkg-config --cflags sqlite3 raylib)
LDFLAGS  = $(shell pkg-config --libs sqlite3 raylib)

TARGET = cti_graph

SRCS = main.cpp \
       src/graph.cpp \
       src/synthetic_data.cpp \
       src/database.cpp \
       src/algorithms.cpp \
       src/service.cpp \
       src/gui.cpp \
       src/tests.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *.db

run: $(TARGET)        # abre a interface gráfica
	./$(TARGET)

menu: $(TARGET)       # menu de texto (operações da Fase 4)
	./$(TARGET) --menu

demo: $(TARGET)       # demonstração de texto não interativa
	./$(TARGET) --demo

test: $(TARGET)       # bateria de testes
	./$(TARGET) --testes

.PHONY: all clean run menu demo test
