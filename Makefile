CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -O2

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
PREFIX ?= /usr/local

CC ?= cc
AR ?= ar

LUA_DIR := third_party/lua
LUA_SRCS := $(wildcard $(LUA_DIR)/*.c)
LUA_OBJS := $(patsubst $(LUA_DIR)/%.c,build/lua/%.o,$(LUA_SRCS))
LUA_LIB := build/liblua.a

CXXFLAGS += -DHAVE_LUA -I$(LUA_DIR)

LIB_SRCS := $(wildcard core/*.cpp device/*.cpp link/*.cpp engine/*.cpp topo/*.cpp)
APP_SRCS := $(wildcard app/*.cpp)
SRCS := $(LIB_SRCS) $(APP_SRCS) script/LuaScript.cpp
LDLIBS := $(LUA_LIB) -lm

OBJS := $(SRCS:.cpp=.o)
DEPS := $(OBJS:.o=.d)
TARGET := netsim

SANFLAGS := -std=c++17 -Wall -Wextra -Werror -O1 -g \
            -fsanitize=address,undefined -fno-omit-frame-pointer -I.

UNIT_SRC := tests/unit/unit_tests.cpp
UNIT_BIN := build/unit_tests
FUZZ_SRC := tests/fuzz_parsers.cpp
FUZZ_BIN := build/fuzz_parsers

.PHONY: all clean test unit fuzz san tidy dist install

TIDY ?= clang-tidy

all: $(TARGET)

$(TARGET): $(OBJS) $(LUA_LIB)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

build/lua/%.o: $(LUA_DIR)/%.c
	@mkdir -p build/lua
	$(CC) -O2 -I$(LUA_DIR) -c $< -o $@

$(LUA_LIB): $(LUA_OBJS)
	$(AR) rcs $@ $^

$(UNIT_BIN): $(UNIT_SRC) $(LIB_SRCS)
	@mkdir -p build
	$(CXX) $(SANFLAGS) $(UNIT_SRC) $(LIB_SRCS) -o $@

$(FUZZ_BIN): $(FUZZ_SRC) $(LIB_SRCS)
	@mkdir -p build
	$(CXX) $(SANFLAGS) $(FUZZ_SRC) $(LIB_SRCS) -o $@

unit: $(UNIT_BIN)
	./$(UNIT_BIN)

fuzz: $(FUZZ_BIN)
	./$(FUZZ_BIN)

san: $(UNIT_BIN) $(FUZZ_BIN)
	ASAN_OPTIONS=detect_leaks=1 ./$(UNIT_BIN)
	ASAN_OPTIONS=detect_leaks=1 ./$(FUZZ_BIN)

tidy:
	@for f in $(LIB_SRCS) $(APP_SRCS); do \
		echo "clang-tidy $$f"; \
		$(TIDY) $$f -- -std=c++17 -I. $(LUA_CFLAGS) || exit 1; \
	done

dist: $(TARGET)
	@mkdir -p dist
	tar czf dist/yanas-net-$(VERSION).tar.gz \
		--exclude='*.o' --exclude='*.a' --exclude='*.d' \
		$(TARGET) win docs third_party packaging Makefile Makefile.win \
		$(if $(wildcard netsim.exe),netsim.exe) \
		README.md LICENSE THIRD_PARTY_NOTICES.md VERSION CHANGELOG.md DEVELOPMENT_LOG.md
	@echo "wrote dist/yanas-net-$(VERSION).tar.gz"

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/netsim
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 docs/netsim.1 $(DESTDIR)$(PREFIX)/share/man/man1/netsim.1
	@echo "installed netsim to $(DESTDIR)$(PREFIX)/bin"

test: $(UNIT_BIN) $(FUZZ_BIN) $(TARGET)
	ASAN_OPTIONS=detect_leaks=1 ./$(UNIT_BIN)
	ASAN_OPTIONS=detect_leaks=1 ./$(FUZZ_BIN)
	bash tests/run_tests.sh

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
	rm -f script/*.o script/*.d
	rm -rf build

-include $(DEPS)
