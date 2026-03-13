/*
 * s1n2_uplane.h – U-Plane setup API
 *
 * Provides clean helper functions that C-Plane code calls to:
 *   1) Decide the S1-U endpoint (IP + TEID) to advertise to the eNB
 *   2) Register downlink  TEID mappings  (UPF N3 TEID → eNB S1-U TEID)
 *   3) Register uplink   TEID mappings  (eNB S1-U TEID → UPF N3 TEID)
 *   4) Perform deferred mapping when UPF info arrives after ICS completion
 *
 * Dependency direction: C-Plane → U-Plane (one-way).
 * U-Plane MUST NOT depend on NAS, ASN.1, or converter internals.
 */
#ifndef S1N2_UPLANE_H
#define S1N2_UPLANE_H

#include <stdint.h>
#include <stdbool.h>

/* Forward declarations – avoid pulling in full converter header */
typedef struct s1n2_context s1n2_context_t;
typedef struct ue_id_mapping ue_id_mapping_t;

/* ------------------------------------------------------------------ */
/*  1) S1-U endpoint selection for InitialContextSetupRequest          */
/* ------------------------------------------------------------------ */

/**
 * s1n2_uplane_select_s1u_endpoint – Determine the S1-U IP and TEID
 *   that will be advertised to the eNB in the ICS Request.
 *
 * Priority: cached E-RAB ctx → S1U_ADVERTISE_ADDR env →
 *           ctx->s1u_addr bind → UPF_S1U_ADDR env → default.
 *
 * Outputs (network byte order): *s1u_ip_be, *s1u_teid_be, *e_rab_id.
 * Also stores s1n2's uplink TEID in ue_map when a fresh TEID is allocated.
 *
 * Returns  0 on success, -1 on error.
 */
int s1n2_uplane_select_s1u_endpoint(const s1n2_context_t *ctx,
                                    ue_id_mapping_t       *ue_map,
                                    uint32_t *s1u_ip_be,
                                    uint32_t *s1u_teid_be,
                                    uint8_t  *e_rab_id);

/* ------------------------------------------------------------------ */
/*  2) TEID mapping registration helpers                               */
/* ------------------------------------------------------------------ */

/**
 * s1n2_uplane_register_ics_erab – Register bidirectional TEID mapping
 *   from an E-RAB entry inside S1AP InitialContextSetupResponse.
 *
 * Called by the S1AP dispatcher when it processes ICS Response
 * (formerly the inline block in s1n2_handle_s1c_message).
 *
 * @param ctx          converter context (for N3 addr fallback)
 * @param ue_map       UE mapping (carries upf_n3_* / enb_s1u_* state)
 * @param s1u_teid     eNB S1-U TEID (host byte order)
 * @param s1u_ip_be    eNB S1-U IP   (network byte order)
 * @param e_rab_id     E-RAB ID
 * @param pdu_session_id  mapped PDU Session ID
 *
 * Returns  >0 on success (N3 TEID), 0 if nothing to do, -1 on error.
 */
int s1n2_uplane_register_ics_erab(const s1n2_context_t *ctx,
                                  ue_id_mapping_t      *ue_map,
                                  uint32_t              s1u_teid,
                                  uint32_t              s1u_ip_be,
                                  uint16_t              e_rab_id,
                                  uint8_t               pdu_session_id);

/**
 * s1n2_uplane_register_dl_mapping – Register downlink TEID mapping
 *   (UPF N3 → eNB S1-U) from a fully-decoded ICS Response.
 *
 * Called by s1n2_convert_initial_context_setup_response()
 * after it extracts eNB IP / TEID from the S1AP message.
 */
int s1n2_uplane_register_dl_mapping(uint32_t enb_teid,
                                    uint32_t enb_ip_be,
                                    uint32_t upf_n3_teid,
                                    uint32_t upf_n3_ip_be,
                                    uint8_t  pdu_session_id,
                                    uint16_t e_rab_id);

/**
 * s1n2_uplane_store_upf_n3_and_map – Store UPF N3 tunnel info from
 *   NGAP PDUSessionResourceSetupRequest, and create any deferred
 *   uplink / downlink TEID mappings that are now possible.
 *
 * Called by the NGAP dispatcher when it receives AMF's ICS Request.
 *
 * @param ctx          converter context
 * @param ue_map       UE mapping (will be updated with upf_n3_*)
 * @param upf_ip_be    UPF N3 IP (network byte order)
 * @param upf_teid     UPF N3 downlink TEID (host byte order)
 * @param pdu_session_id  PDU Session ID
 * @param e_rab_id     original E-RAB ID (for mapping table)
 */
void s1n2_uplane_store_upf_n3_and_map(s1n2_context_t  *ctx,
                                      ue_id_mapping_t *ue_map,
                                      uint32_t         upf_ip_be,
                                      uint32_t         upf_teid,
                                      uint8_t          pdu_session_id,
                                      uint8_t          e_rab_id);

#endif /* S1N2_UPLANE_H */
