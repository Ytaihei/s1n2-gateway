.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

# ---- open5gs 取得設定 ----
OPEN5GS_COMMIT := 234da30d930a5697f80fe248886ea6cec98ec12d
OPEN5GS_URL    := https://github.com/open5gs/open5gs.git

# open5gs が未取得の場合のみ自動フェッチしてから再ビルド
# (wildcard はパース時評価なので、取得後に $(MAKE) を再起動して変数を再評価させる)
ifeq ($(wildcard open5gs/lib/asn1c/common/asn_internal.h),)
.PHONY: all
all:
	@$(MAKE) fetch-open5gs
	@$(MAKE) _build
else
.PHONY: all
all: _build
endif

.PHONY: fetch-open5gs
fetch-open5gs:
	@echo "[INFO] Fetching open5gs $(OPEN5GS_COMMIT) ..."
	@rm -rf open5gs
	git init open5gs
	git -C open5gs remote add origin $(OPEN5GS_URL)
	git -C open5gs fetch --filter=blob:none --depth=1 origin $(OPEN5GS_COMMIT)
	git -C open5gs sparse-checkout init --cone
	git -C open5gs sparse-checkout set lib/asn1c/common lib/asn1c/ngap
	git -C open5gs checkout FETCH_HEAD
	@echo "[INFO] open5gs fetched."

CC := gcc
CFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -std=c11 -D_POSIX_C_SOURCE=200809L \
	-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_JER_SUPPORT -DASN_DISABLE_XER_SUPPORT \
	-DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_DER_SUPPORT \
	-include ./include/ogs_compat.h \
	-I./include -I./include/internal -I./src -I./src/cplane/nas -I./src/cplane/s1ap_ngap $(addprefix -I,$(wildcard src/cplane/s1ap_ngap/*/))  -I./include/s1ap -I./open5gs/lib/asn1c/common -I./open5gs/lib/asn1c/ngap
# 将来 asn1c コード最小化時に -Os -ffunction-sections -Wl,--gc-sections などへ調整予定
LDFLAGS := -lsctp -lssl -lcrypto -lyaml

# ASN.1 ランタイム
# これまで wildcard で *.c 全投入していたが、JER/XER/OER/BER/DER を無効化マクロで
# 切っている状態で *_jer.c / *_xer.c / *_oer.c / ber_*.c / der_*.c / oer_*.c / xer_*.c を
# 同時にコンパイルすると無効化により型や列挙定義が消えるため "incomplete type" 等
# のエラーになる。APER + 汎用ヘルパのみを残すため以下で除外フィルタを適用する。
ASN1_RUNTIME_SRCS_ALL := $(wildcard open5gs/lib/asn1c/common/*.c)
ASN1_RUNTIME_UNWANTED := $(wildcard \
	open5gs/lib/asn1c/common/*_jer.c \
	open5gs/lib/asn1c/common/jer_*.c \
	open5gs/lib/asn1c/common/*_xer.c \
	open5gs/lib/asn1c/common/*_oer.c \
	open5gs/lib/asn1c/common/ber_*.c \
	open5gs/lib/asn1c/common/der_*.c \
	open5gs/lib/asn1c/common/oer_*.c \
	open5gs/lib/asn1c/common/xer_*.c)
ASN1_RUNTIME_SRCS := $(filter-out $(ASN1_RUNTIME_UNWANTED),$(ASN1_RUNTIME_SRCS_ALL))

# デバッグ用: 必要なら `make print-asn1` で最終リスト確認
.PHONY: print-asn1
print-asn1:
	@echo "ASN1_RUNTIME_SRCS has $(words $(ASN1_RUNTIME_SRCS)) files"

# Open5GS の正式なビルド対象を使用する。ディレクトリには旧 ASN.1
# 生成コードも残っており、*.c の全投入では現行ヘッダーと整合しない。
NGAP_MANIFEST := open5gs/lib/asn1c/ngap/meson.build
NGAP_SRCS := $(addprefix open5gs/lib/asn1c/ngap/,$(shell \
	if [ -f $(NGAP_MANIFEST) ]; then \
		sed -n 's/^[[:space:]]*\([A-Za-z0-9_-]*\.c\)[[:space:]]*$$/\1/p' $(NGAP_MANIFEST); \
	fi))
S1AP_SRCS := $(wildcard include/s1ap/*.c)

# 段階的ビルド: まずソースファイルをコンパイル
# `src/` 配下の `.c` を再帰的に収集し、将来ディレクトリを追加しても自動追従する
SRC_FIND := $(shell find src -type f -name '*.c')
SRC := $(sort $(SRC_FIND))
BIN := build/s1n2-converter

# オブジェクト分割 (Argument list too long 回避 & 再ビルド効率化)
OBJS := $(patsubst %.c,build/obj/%.o,$(SRC))
OBJS_NO_MAIN := $(filter-out build/obj/src/app/main.o,$(OBJS))
ASN1_OBJS := $(patsubst %.c,build/obj/%.o,$(ASN1_RUNTIME_SRCS))
NGAP_OBJS := $(patsubst %.c,build/obj/%.o,$(NGAP_SRCS))
S1AP_OBJS := $(patsubst %.c,build/obj/%.o,$(S1AP_SRCS))

# 大量オブジェクト問題解決: 静的ライブラリ作成
LIBNGAP := build/lib/libngap.a
LIBS1AP := build/lib/libs1ap.a

# ヘッダー変更と Makefile の変更も再ビルドへ反映する。
build/obj/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# オブジェクトごとの依存関係で、並列・差分ビルドと失敗の伝播を保つ。
# アーカイブは作り直し、旧オブジェクト名のメンバーを残さない。
$(LIBNGAP): $(NGAP_OBJS)
	@mkdir -p $(dir $@)
	$(RM) $@
	$(AR) rcs $@ $^

$(LIBS1AP): $(S1AP_OBJS)
	@mkdir -p $(dir $@)
	$(RM) $@
	$(AR) rcs $@ $^

.PHONY: _build clean print-objs asn1-objs libs tests test

print-objs:
	@printf 'OBJS count=%s\n' $(words $(OBJS))
	@printf '%s\n' $(OBJS) | xargs -n 20 echo

asn1-objs: $(ASN1_OBJS)

libs: $(LIBNGAP) $(LIBS1AP)

TEST_SRC_FIND := $(sort $(shell if [ -d tests ]; then find tests -type f -name '*.c'; fi))
TEST_EXCLUDES := tests/stubs.c
TEST_SRCS := $(filter-out $(TEST_EXCLUDES),$(TEST_SRC_FIND))
TEST_OBJS := $(patsubst %.c,build/obj/%.o,$(TEST_SRCS))
TEST_BINS := $(patsubst tests/%.c,build/tests/%,$(TEST_SRCS))

$(OBJS) $(TEST_OBJS): CFLAGS += -Werror=implicit-function-declaration

_build: $(BIN)

ifeq ($(strip $(TEST_SRCS)),)
tests test:
	@echo "[ERROR] No unit test sources found under tests/." >&2
	@exit 1
else
tests: $(TEST_BINS)

test: tests
	@set -e; for test_bin in $(TEST_BINS); do "./$$test_bin"; done
endif

$(BIN): $(OBJS) $(ASN1_OBJS) $(LIBNGAP) $(LIBS1AP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(ASN1_OBJS) $(LIBNGAP) $(LIBS1AP) $(LDFLAGS)

build/tests/%: build/obj/tests/%.o $(OBJS_NO_MAIN) $(ASN1_OBJS) $(LIBNGAP) $(LIBS1AP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf build

# テストオブジェクトを中間ファイルとして削除させない。
.SECONDARY: $(TEST_OBJS)
DEPS := $(OBJS:.o=.d) $(ASN1_OBJS:.o=.d) $(NGAP_OBJS:.o=.d) $(S1AP_OBJS:.o=.d) $(TEST_OBJS:.o=.d)
-include $(DEPS)
