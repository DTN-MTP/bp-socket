#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <pthread.h>

static pthread_mutex_t sdrmutex = PTHREAD_MUTEX_INITIALIZER;

const char *bp_result_text(BpIndResult result) {
    switch (result) {
    case BpPayloadPresent:
        return "BpPayloadPresent";
    case BpReceptionTimedOut:
        return "BpReceptionTimedOut";
    case BpReceptionInterrupted:
        return "BpReceptionInterrupted";
    case BpEndpointStopped:
        return "BpEndpointStopped";
    default:
        return "Unknown";
    }
}

int bp_send_to_eid(Sdr sdr, char *payload, int payload_size, char *dest_eid, int eid_size) {
    Object sdrBuffer;
    Object zco;

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

    if (bp_send(NULL, dest_eid, NULL, 86400, BP_STD_PRIORITY, 0, 0, 0, NULL, zco, NULL) <= 0) {
        sdr_end_xn(sdr);
        log_error("bp_send failed.");
        return 0;
    }

    sdr_end_xn(sdr);
    return 1;
}

int bp_recv_once(Sdr sdr, int service_id, char **payload) {
    BpSAP sap;
    BpDelivery dlv;
    ZcoReader reader;
    int bundle_len;
    int rc = -1;
    int eid_size;
    char eid[64];
    int nodeNbr = getOwnNodeNbr();

    eid_size = snprintf(eid, sizeof(eid), "ipn:%d.%d", nodeNbr, service_id);
    if (eid_size < 0 || eid_size >= sizeof(eid)) {
        log_error("Failed to construct EID string.");
        return -1;
    }

    if (bp_open(eid, &sap) < 0) {
        log_error("bp_recv_once: Failed to open BpSAP for node_id=%d service_id=%d", nodeNbr,
                  service_id);
        return -1;
    }

    if (bp_receive(sap, &dlv, BP_BLOCKING) < 0) {
        log_error("bp_recv_once: Bundle reception failed.");
        goto out;
    }

    if (dlv.result != BpPayloadPresent || dlv.adu == 0) {
        log_error("bp_recv_once: %s", bp_result_text(dlv.result));
        goto out;
    }

    if (pthread_mutex_lock(&sdrmutex) != 0) {
        putErrmsg("Couldn't take sdr mutex.", NULL);
        goto out;
    }

    if (sdr_begin_xn(sdr) == 0) goto out;

    bundle_len = zco_source_data_length(sdr, dlv.adu);
    *payload = malloc(bundle_len);
    if (!*payload) {
        log_error("bp_recv_once: Failed to allocate memory for payload.");
        goto unlock_sdr;
    }

    zco_start_receiving(dlv.adu, &reader);
    rc = zco_receive_source(sdr, &reader, bundle_len, *payload);

    sdr_end_xn(sdr);
unlock_sdr:
    pthread_mutex_unlock(&sdrmutex);

out:
    bp_release_delivery(&dlv, 0);
    bp_close(sap);

    return rc;
}
