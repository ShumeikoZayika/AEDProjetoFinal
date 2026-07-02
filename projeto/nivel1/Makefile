CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

TARGET = cti_graph

SRCS = main.cpp \
       src/graph.cpp \
       src/synthetic_data.cpp \
       src/tests.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./$(TARGET) --testes

.PHONY: all clean run test
