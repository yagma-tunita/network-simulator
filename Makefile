CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
WERROR ?= 1
ifeq ($(WERROR),1)
CXXFLAGS += -Werror
endif
COVERAGE ?= 0

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
PREFIX ?= /usr/local

CC ?= cc
GO ?= go
AR ?= ar

LUA_DIR := third_party/lua
BUILD ?= build
LUA_SRCS := $(wildcard $(LUA_DIR)/*.c)
LUA_OBJS := $(patsubst $(LUA_DIR)/%.c,$(BUILD)/lua/%.o,$(LUA_SRCS))
LUA_LIB := $(BUILD)/liblua.a

CXXFLAGS += -DHAVE_LUA -I$(LUA_DIR)

ifeq ($(COVERAGE),1)
CXXFLAGS += -O0 -g --coverage
COVERAGE_LDFLAGS := --coverage
endif

LIB_SRCS := $(wildcard core/*.cpp device/*.cpp device/end/*.cpp device/router/*.cpp link/*.cpp engine/*.cpp topo/*.cpp netstack/*.cpp)
APP_SRCS := $(wildcard app/*.cpp)
SRCS := $(LIB_SRCS) $(APP_SRCS) script/LuaScript.cpp
LDLIBS := $(LUA_LIB) -lm

OBJS := $(patsubst %.cpp,$(BUILD)/obj/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)
TARGET := netsim

SANFLAGS := -std=c++17 -Wall -Wextra -Werror -O1 -g \
            -fsanitize=address,undefined -fno-omit-frame-pointer -I.

UNIT_SRC := tests/unit/unit_tests.cpp
UNIT_BIN := $(BUILD)/unit_tests
FUZZ_SRC := tests/fuzz_parsers.cpp
FUZZ_BIN := $(BUILD)/fuzz_parsers

.PHONY: all clean test unit fuzz san tidy dist install coverage soak perf check tools gotest pcapcheck

TIDY ?= clang-tidy

all: $(TARGET)

$(TARGET): $(OBJS) $(LUA_LIB)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDLIBS) $(COVERAGE_LDFLAGS)

$(BUILD)/obj/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/lua/%.o: $(LUA_DIR)/%.c
	@mkdir -p $(BUILD)/lua
	$(CC) -O2 -I$(LUA_DIR) -c $< -o $@

$(LUA_LIB): $(LUA_OBJS)
	$(AR) rcs $@ $^

$(UNIT_BIN): $(UNIT_SRC) $(LIB_SRCS)
	@mkdir -p $(BUILD)
	$(CXX) $(SANFLAGS) $(UNIT_SRC) $(LIB_SRCS) -o $@

$(FUZZ_BIN): $(FUZZ_SRC) $(LIB_SRCS)
	@mkdir -p $(BUILD)
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
		--exclude='*.o' --exclude='*.a' --exclude='*.d' --exclude='dist' \
		core device link engine topo netstack app script tests win docs examples third_party packaging tools \
		CMakeLists.txt Makefile Makefile.win .github .clang-tidy .gitignore .gitattributes \
		$(TARGET) \
		$(if $(wildcard netsim.exe),netsim.exe) \
		README.md LICENSE COPYRIGHT THIRD_PARTY_NOTICES.md SOURCE-CODE.md \
		CONTRIBUTING.md SECURITY.md VERSION CHANGELOG.md DEVELOPMENT_LOG.md
	@echo "wrote dist/yanas-net-$(VERSION).tar.gz"

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/netsim
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 docs/netsim.1 $(DESTDIR)$(PREFIX)/share/man/man1/netsim.1
	@echo "installed netsim to $(DESTDIR)$(PREFIX)/bin"

coverage:
	bash tests/coverage.sh

soak:
	bash tests/soak.sh

perf:
	bash tests/perf.sh

check: test gotest coverage soak perf pcapcheck
	@echo "check complete"

tools:
	@mkdir -p build
	cd tools/ynstress && $(GO) build -o ../../build/ynstress ./cmd/ynstress
	cd tools/ynpcap && $(GO) build -o ../../build/ynpcap ./cmd/ynpcap
	@echo "built build/ynstress and build/ynpcap"

gotest:
	cd tools/ynstress && $(GO) test ./...
	cd tools/ynpcap && $(GO) test ./...

pcapcheck: tools $(TARGET)
	bash tests/pcap_conformance.sh

test: $(UNIT_BIN) $(FUZZ_BIN) $(TARGET)
	ASAN_OPTIONS=detect_leaks=1 ./$(UNIT_BIN)
	ASAN_OPTIONS=detect_leaks=1 ./$(FUZZ_BIN)
	bash tests/run_tests.sh

clean:
	rm -f $(TARGET)
	rm -rf build
	find . \( -name '*.o' -o -name '*.d' \) -delete 2>/dev/null || true
	find . \( -name '*.gcda' -o -name '*.gcno' \) -delete 2>/dev/null || true
	rm -f *.gcov

-include $(DEPS)
