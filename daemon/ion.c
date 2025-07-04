#include "log.h"
#include "sdr.h"
#include <bp.h>

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

char *bp_recv_once(int service_id) {
    BpSAP txSap;
    BpDelivery dlv;
    Sdr sdr = getIonsdr();
    ZcoReader reader;
    char *eid = NULL;
    char *payload = NULL;
    int eid_size;
    int nodeNbr = getOwnNodeNbr();
    vast len;

    eid_size = snprintf(NULL, 0, "ipn:%d.%d", nodeNbr, service_id) + 1;
    eid = malloc(eid_size);
    if (!eid) {
        log_error("Failed to allocate EID");
        return NULL;
    }
    snprintf(eid, eid_size, "ipn:%d.%d", nodeNbr, service_id);

    if (bp_open(eid, &txSap) < 0 || txSap == NULL) {
        log_error("Failed to open source endpoint.");
        goto out;
    }

    if (bp_receive(txSap, &dlv, BP_BLOCKING) < 0) {
        log_error("Bundle reception failed.");
        goto out;
    }

    if (dlv.result != BpPayloadPresent) {
        log_info("bp_recv_once: no payload");
        goto out;
    }

    if (!sdr_begin_xn(sdr)) goto out;

    int payload_size = zco_source_data_length(sdr, dlv.adu);
    payload = malloc(payload_size);
    if (!payload) {
        log_error("Failed to allocate memory for payload");
        sdr_exit_xn(sdr);
        goto out;
    }

    zco_start_receiving(dlv.adu, &reader);
    len = zco_receive_source(sdr, &reader, payload_size, payload);

    if (sdr_end_xn(sdr) < 0 || len < 0) {
        log_error("Failed to read payload");
        free(payload);
        payload = NULL;
        goto out;
    }

out:
    if (eid) free(eid);
    bp_release_delivery(&dlv, 0);
    bp_close(txSap);

    return payload;
}
