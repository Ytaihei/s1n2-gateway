.DEFAULT_GOAL := all

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
CFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -std=c11 \
	-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_JER_SUPPORT -DASN_DISABLE_XER_SUPPORT \
	-DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_DER_SUPPORT \
	-include ./include/ogs_compat.h \
	-I./include -I./include/internal -I./src -I./src/cplane/nas -I./src/cplane/s1ap_ngap -I./src/cplane/s1ap_ngap/*/  -I./include/s1ap -I./open5gs/lib/asn1c/common -I./open5gs/lib/asn1c/ngap
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

# 上記リストは存在するファイル名のみ残し、不足/余剰があれば調整 (簡便のため make 失敗時に再編集)

# (方針変更) Open5GS の asn1c 生成 NGAP 実装を使用する
# Argument list too long回避のため、静的ライブラリ方式に変更
# NGAP_ProtocolIE-Field.c等、NGAP_で始まらない重要ファイルも含める必要
NGAP_SRCS := $(wildcard open5gs/lib/asn1c/ngap/*.c)
S1AP_SRCS := $(wildcard include/s1ap/*.c)

# 段階的ビルド: まずソースファイルをコンパイル
# `src/` 配下の `.c` を再帰的に収集し、将来ディレクトリを追加しても自動追従する
SRC_EXCLUDES := src/transport/gtp_tunnel_mock.c src/core/s1n2_converter_simple.c
SRC_FIND := $(shell find src -type f -name '*.c')
SRC := $(filter-out $(SRC_EXCLUDES),$(sort $(SRC_FIND)))
BIN := build/s1n2-converter

# オブジェクト分割 (Argument list too long 回避 & 再ビルド効率化)
OBJS := $(patsubst %.c,build/obj/%.o,$(SRC))
OBJS_NO_MAIN := $(filter-out build/obj/src/app/main.o,$(OBJS))
ASN1_OBJS := $(patsubst %.c,build/obj/%.o,$(ASN1_RUNTIME_SRCS))

# 大量オブジェクト問題解決: 静的ライブラリ作成
LIBNGAP := build/lib/libngap.a
LIBS1AP := build/lib/libs1ap.a

# Debug info disabled to avoid infinite loop
# $(info [INFO] OBJS count=$(words $(OBJS)))
# $(info [INFO] ASN1_OBJS count=$(words $(ASN1_OBJS)))
# $(info [INFO] NGAP_SRCS count=$(words $(NGAP_SRCS)))
# $(info [INFO] S1AP_SRCS count=$(words $(S1AP_SRCS)))

build/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# 静的ライブラリ作成ルール
$(LIBNGAP): $(NGAP_SRCS)
	@mkdir -p $(dir $@)
	@echo "[INFO] Building NGAP library with $(words $^) objects..."
	@for src in $^; do \
		obj=build/obj/$$src.o; \
		mkdir -p $$(dirname $$obj); \
		$(CC) $(CFLAGS) -c $$src -o $$obj; \
	done
	@ar rcs $@ build/obj/open5gs/lib/asn1c/ngap/NGAP_*.o
	@echo "[INFO] NGAP library created: $@"

$(LIBS1AP): $(S1AP_SRCS)
	@mkdir -p $(dir $@)
	@if [ -n "$^" ]; then \
		echo "[INFO] Building S1AP library with $(words $^) objects..."; \
		for src in $^; do \
			obj=build/obj/$$src.o; \
			mkdir -p $$(dirname $$obj); \
			$(CC) $(CFLAGS) -c $$src -o $$obj; \
		done; \
		ar rcs $@ build/obj/include/s1ap/*.o; \
		echo "[INFO] S1AP library created: $@"; \
	else \
		echo "[INFO] No S1AP sources found, creating empty library"; \
		ar rcs $@; \
	fi

.PHONY: _build clean print-objs asn1-objs libs tests test

print-objs:
	@printf 'OBJS count=%s\n' $(words $(OBJS))
	@printf '%s\n' $(OBJS) | xargs -n 20 echo

asn1-objs: $(ASN1_OBJS)

libs: $(LIBNGAP) $(LIBS1AP)

TEST_SRC_FIND := $(sort $(shell find tests -type f -name '*.c'))
TEST_EXCLUDES := tests/stubs.c
TEST_SRCS := $(filter-out $(TEST_EXCLUDES),$(TEST_SRC_FIND))
TEST_OBJS := $(patsubst %.c,build/obj/%.o,$(TEST_SRCS))
TEST_BINS := $(patsubst tests/%.c,build/tests/%,$(TEST_SRCS))

_build: $(BIN)

tests: $(TEST_BINS)

test: tests

$(BIN): $(OBJS) $(ASN1_OBJS) $(LIBNGAP) $(LIBS1AP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(ASN1_OBJS) $(LIBNGAP) $(LIBS1AP) $(LDFLAGS)

build/tests/%: build/obj/tests/%.o $(OBJS_NO_MAIN) $(ASN1_OBJS) $(LIBNGAP) $(LIBS1AP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf build


