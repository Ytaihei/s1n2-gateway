/*
 * s1n2_converter_internal.h – Common includes for per-message converter modules
 *
 * This header aggregates all standard, project, and ASN.1 headers needed by
 * the converter sub-modules (setup, initial_ue, nas_transport, ics, dispatcher).
 * Include this single header instead of duplicating the ~90-line include block.
 */
#ifndef S1N2_CONVERTER_INTERNAL_H
#define S1N2_CONVERTER_INTERNAL_H

/* Standard C */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <poll.h>
#include <time.h>
#include <errno.h>

/* Project headers */
#include "s1n2_converter.h"
#include "internal/s1n2_context_internal.h"
#include "internal/s1n2_nas_internal.h"
#include "internal/nas_security.h"
#include "internal/protocol_builders.h"
#include "gtp_header.h"
#include "subscriber_auth.h"
#include "s1n2_utils.h"
#include "uplane_setup.h"
#include "suci_utils.h"
#include "gtp_tunnel.h"

/* ASN.1 runtime */
#include <asn_application.h>
#include <aper_decoder.h>

/* S1AP headers */
#include "S1AP_S1AP-PDU.h"
#include "S1AP_InitiatingMessage.h"
#include "S1AP_SuccessfulOutcome.h"
#include "S1AP_UnsuccessfulOutcome.h"
#include "S1AP_S1SetupRequest.h"
#include "S1AP_InitialUEMessage.h"
#include "S1AP_ProtocolIE-Field.h"
#include "S1AP_ProtocolIE-ID.h"
#include "S1AP_ProtocolIE-SingleContainer.h"
#include "S1AP_SupportedTAs.h"
#include "S1AP_SupportedTAs-Item.h"
#include "S1AP_NAS-PDU.h"
#include "S1AP_UEAggregateMaximumBitrate.h"
#include "S1AP_E-RABToBeSetupItemCtxtSUReq.h"
#include "S1AP_E-RABToBeSetupListCtxtSUReq.h"
#include "S1AP_InitialContextSetupRequest.h"
#include "S1AP_InitialContextSetupResponse.h"
#include "S1AP_E-RABSetupListCtxtSURes.h"
#include "S1AP_E-RABSetupItemCtxtSURes.h"
#include "S1AP_E-RABLevelQoSParameters.h"
#include "S1AP_AllocationAndRetentionPriority.h"
#include "S1AP_QCI.h"
#include "S1AP_Cause.h"
#include "S1AP_TransportLayerAddress.h"
#include "S1AP_GTP-TEID.h"
#include "S1AP_UESecurityCapabilities.h"
#include "S1AP_SecurityKey.h"
#include "S1AP_DownlinkNASTransport.h"
#include "S1AP_UplinkNASTransport.h"
#include "S1AP_ProcedureCode.h"
#include "S1AP_ErrorIndication.h"
#include "S1AP_NASNonDeliveryIndication.h"
#include "S1AP_TAI.h"
#include "S1AP_RRC-Establishment-Cause.h"
#include "S1AP_UEContextReleaseRequest.h"

/* NGAP headers */
#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_SuccessfulOutcome.h"
#include "NGAP_NGSetupResponse.h"
#include "NGAP_InitialContextSetupResponse.h"
#include "NGAP_PDUSessionResourceSetupListCxtRes.h"
#include "NGAP_PDUSessionResourceSetupItemCxtRes.h"
#include "NGAP_PDUSessionResourceSetupResponseTransfer.h"
#include "NGAP_QosFlowPerTNLInformation.h"
#include "NGAP_UPTransportLayerInformation.h"
#include "NGAP_GTPTunnel.h"
#include "NGAP_AssociatedQosFlowList.h"
#include "NGAP_AssociatedQosFlowItem.h"
#include "NGAP_QosFlowIdentifier.h"
#include "NGAP_TransportLayerAddress.h"
#include "NGAP_GTP-TEID.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_PDUSessionResourceSetupItemCxtReq.h"
#include "NGAP_DownlinkNASTransport.h"
#include "NGAP_UplinkNASTransport.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_Criticality.h"
#include "NGAP_RRCEstablishmentCause.h"
#include "NGAP_UEContextRequest.h"
#include "NGAP_FiveG-S-TMSI.h"
#include "NGAP_AMF-UE-NGAP-ID.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_UserLocationInformation.h"
#include "NGAP_UserLocationInformationNR.h"
#include "NGAP_NR-CGI.h"
#include "NGAP_TAI.h"
#include "NGAP_ProcedureCode.h"
#include "NGAP_PDUSessionResourceSetupRequest.h"
#include "NGAP_PDUSessionResourceSetupListSUReq.h"
#include "NGAP_PDUSessionResourceSetupItemSUReq.h"
#include "NGAP_PDUSessionResourceSetupRequestTransfer.h"
#include "NGAP_PDUSessionType.h"
#include "NGAP_QosFlowSetupRequestList.h"
#include "NGAP_QosFlowSetupRequestItem.h"
#include "NGAP_QosCharacteristics.h"
#include "NGAP_NonDynamic5QIDescriptor.h"
#include "NGAP_FiveQI.h"
#include "NGAP_ErrorIndication.h"
#include "NGAP_NASNonDeliveryIndication.h"
#include "NGAP_UEContextReleaseRequest.h"
#include "NGAP_Cause.h"

#endif /* S1N2_CONVERTER_INTERNAL_H */
