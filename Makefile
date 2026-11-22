CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -O2

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
PREFIX ?= /usr/local

LUA ?= auto
ifeq ($(LUA),auto)
  ifeq ($(shell pkg-config --exists lua5.4 2>/dev/null && echo yes),yes)
    LUA := 1
  else
    LUA := 0
  endif
endif

LUA_CFLAGS ?= $(shell pkg-config --cflags lua5.4 2>/dev/null)
LUA_LIBS   ?= $(shell pkg-config --libs lua5.4 2>/dev/null)

LIB_SRCS := $(wildcard core/*.cpp device/*.cpp link/*.cpp engine/*.cpp topo/*.cpp)
APP_SRCS := $(wildcard app/*.cpp)
SRCS := $(LIB_SRCS) $(APP_SRCS)
LDLIBS :=

ifeq ($(LUA),1)
CXXFLAGS += -DHAVE_LUA $(LUA_CFLAGS)
SRCS += script/LuaScript.cpp
LDLIBS += $(LUA_LIBS)
endif

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

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

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
		$(TARGET) web win docs Makefile Makefile.win \
		$(if $(wildcard yanasnet.exe),yanasnet.exe) \
		README.md LICENSE VERSION CHANGELOG.md DEVELOPMENT_LOG.md
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
