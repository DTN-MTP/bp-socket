#include "ion.h"
#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <pthread.h>
#include "bp_receive_list.h"

int bp_send_to_eid(char *payload, int payload_size, char *destEid, int eid_size) {
    Sdr sdr;
    Object sdrBuffer;
    Object zco;

    sdr = bp_get_sdr();
    if (sdr == NULL) {
        log_error("*** Failed to get sdr.");
        return 0;
    }

    oK(sdr_begin_xn(sdr));

    sdrBuffer = sdr_malloc(sdr, payload_size);
    if (sdrBuffer == 0) {
        sdr_end_xn(sdr);
        log_error("sdr_malloc failed.");
        return 0;
    }

    sdr_write(sdr, sdrBuffer, payload, payload_size);

    zco = zco_create(sdr, ZcoSdrSource, sdrBuffer, 0, payload_size, ZcoOutbound);
    if (zco == 0 || zco == (Object)ERROR) {
        sdr_end_xn(sdr);
        log_error("zco_create failed.");
        return 0;
    }

    if (bp_send(NULL, destEid, NULL, 86400, BP_STD_PRIORITY, 0, 0, 0, NULL, zco, NULL) <= 0) {
        sdr_end_xn(sdr);
        log_error("bp_send failed.");
        return 0;
    }

    sdr_end_xn(sdr);
    return 1;
}

BpIndResult bp_recv_once(int service_id, char **payload) {
    BpSAP *txSap;
    BpDelivery dlv;
    Sdr sdr = getIonsdr();
    ZcoReader reader;
    char *eid = NULL;
    int eid_size;
    int nodeNbr = getOwnNodeNbr();
    vast len;

    txSap = malloc(sizeof(BpSAP));
    if (!txSap) {
        log_error("Failed to allocate BpSAP");
        return -1;
    }

    eid_size = snprintf(NULL, 0, "ipn:%d.%d", nodeNbr, service_id) + 1;
    eid = malloc(eid_size);
    if (!eid) {
        log_error("Failed to allocate EID");
        goto free_sap;
    }
    snprintf(eid, eid_size, "ipn:%d.%d", nodeNbr, service_id);

    if (bp_open(eid, txSap) < 0) {
        log_error("Failed to open source endpoint.");
        goto free_eid;
    }

    bp_receive_list_add(nodeNbr, service_id, txSap);

    if (bp_receive(*txSap, &dlv, BP_BLOCKING) < 0) {
        log_error("Bundle reception failed.");
        goto out;
    }

    switch (dlv.result) {
    case BpPayloadPresent:
        if (!sdr_begin_xn(sdr)) {
            goto out;
        }

        int payload_size = zco_source_data_length(sdr, dlv.adu);
        *payload = malloc(payload_size);
        if (!*payload) {
            log_error("Failed to allocate memory for payload");
            sdr_exit_xn(sdr);
            goto out;
        }

        zco_start_receiving(dlv.adu, &reader);
        len = zco_receive_source(sdr, &reader, payload_size, *payload);

        if (sdr_end_xn(sdr) < 0 || len < 0) {
            log_error("Failed to read payload");
            free(*payload);
            *payload = NULL;
            goto out;
        }
        break;
    case BpReceptionInterrupted:
        break;
    default:
        log_error("bp_recv_once: unexpected result %d", dlv.result);
    }

out:
    bp_release_delivery(&dlv, 1);
    bp_receive_list_remove(nodeNbr, service_id);
    bp_close(*txSap);
free_eid:
    free(eid);
free_sap:
    free(txSap);

    return dlv.result;
}

void bp_cancel_recv_once(uint32_t node_id, uint32_t service_id) {
    BpSAP* sap = bp_receive_list_find(node_id, service_id);

    if (sap == NULL) {
        log_error("bp_interrupt: BpSAP is NULL");
        return;
    }

    bp_interrupt(*sap);
}