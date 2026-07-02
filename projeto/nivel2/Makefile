CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 \
           -I/opt/homebrew/Cellar/sqlite/3.53.0/include
LDFLAGS  = -L/opt/homebrew/Cellar/sqlite/3.53.0/lib -lsqlite3

TARGET = cti_graph

SRCS = main.cpp \
       src/graph.cpp \
       src/synthetic_data.cpp \
       src/database.cpp \
       src/tests.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *.db

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./$(TARGET) --testes

.PHONY: all clean run test
