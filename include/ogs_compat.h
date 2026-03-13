/**
 * ogs_compat.h — Open5GS マクロを標準 libc へマッピングする互換ヘッダ
 *
 * open5gs/lib/asn1c/common/ は通常 Open5GS コアライブラリ (ogs_malloc 等) に
 * 依存するが、s1n2 は Open5GS コアをリンクしない。
 * このファイルを -include で強制インクルードすることで、Open5GS ソースを
 * 無改変のまま使用できる。
 *
 * 使い方: CFLAGS に -include $(S1N2_ROOT)/include/ogs_compat.h を追加する。
 */

#pragma once

#include <stdlib.h>
#include <stdio.h>

/* ---- 基本マクロ ---- */
#define ogs_inline inline

#define OGS_STRINGIFY_INNER(x) #x
#define OGS_STRINGIFY(x)       OGS_STRINGIFY_INNER(x)
#define OGS_FILE_LINE          __FILE__ ":" OGS_STRINGIFY(__LINE__)

/* ---- メモリ管理: libc に委譲 ---- */
#define ogs_malloc(size)           malloc(size)
#define ogs_calloc(nmemb, size)    calloc(nmemb, size)
#define ogs_realloc(oldptr, size)  realloc(oldptr, size)
#define ogs_free(ptr)              free(ptr)

/* ---- エラー処理: stderr に出力して abort ---- */
#define ogs_fatal(fmt, ...)  \
    do { fprintf(stderr, "[FATAL] " fmt "\n", ##__VA_ARGS__); abort(); } while (0)

#define ogs_assert_if_reached() abort()
