/*
 * ogs-proto.h stub — provides OGS macro compatibility without the full Open5GS core.
 * All actual definitions are supplied by ogs_compat.h (injected via -include).
 * This file exists solely to satisfy the #include "proto/ogs-proto.h" in
 * open5gs/lib/asn1c/common/asn_internal.h.
 */
#ifndef OGS_PROTO_STUB_H
#define OGS_PROTO_STUB_H

/* ogs_compat.h is already injected via -include before any TU is compiled,
 * so all required macros (ogs_malloc, ogs_free, ogs_fatal, ogs_inline, ...) are
 * already defined.  Nothing further is needed here. */

#endif /* OGS_PROTO_STUB_H */
