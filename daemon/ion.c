#include "ion.h"
#include "bp_sap_registry.h"
#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <pthread.h>

static pthread_mutex_t sdrmutex = PTHREAD_MUTEX_INITIALIZER;

int bp_open_and_register(uint32_t node_id, uint32_t service_id) {
    BpSAP sap;
    char eid[64];
    int eid_size;
    Sdr sdr = getIonsdr();

    if (sdr == NULL) {
        log_error("Failed to get SDR.");
        return -1;
    }

    eid_size = snprintf(eid, sizeof(eid), "ipn:%u.%u", node_id, service_id);
    if (eid_size < 0 || eid_size >= (int)sizeof(eid)) {
        log_error("Failed to construct EID string.");
        return -1;
    }

    memset(&sap, 0, sizeof(BpSAP));
    if (bp_open(eid, &sap) < 0) {
        log_error("Failed to open source endpoint.");
        return -1;
    }

    bp_sap_registry_add(node_id, service_id, sap);

    return 0;
}

int bp_close_and_unregister(uint32_t node_id, uint32_t service_id) {
    BpSAP sap = bp_sap_registry_find(node_id, service_id);
    if (sap == NULL) {
        log_error("bp_close_and_unregister: BpSAP is NULL");
        return -1;
    }

    bp_close(sap);
    bp_sap_registry_remove(node_id, service_id);

    return 0;
}

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

int bp_recv_once(Sdr sdr, int service_id, char **payload) {
    BpSAP sap;
    BpDelivery dlv;
    ZcoReader reader;
    int bundleLen;
    int rc = -1;
    int nodeNbr = getOwnNodeNbr();
    char eid[64];
    int eid_size;

    eid_size = snprintf(eid, sizeof(eid), "ipn:%u.%u", nodeNbr, service_id);
    if (eid_size < 0 || eid_size >= (int)sizeof(eid)) {
        log_error("Failed to construct EID string.");
        return rc;
    }

    if (bp_open(eid, &sap) < 0) {
        log_error("bp_recv_once: Failed to open BpSAP for node_id=%d service_id=%d", nodeNbr,
                  service_id);
        return rc;
    }

    if (bp_receive(sap, &dlv, BP_BLOCKING) < 0) {
        log_error("bp_recv_once: Bundle reception failed.");
        goto out;
    }

    if (dlv.result != BpPayloadPresent || dlv.adu == 0) {
        bp_release_delivery(&dlv, 1);
        goto out;
    }

    if (pthread_mutex_lock(&sdrmutex) != 0) {
        putErrmsg("Couldn't take sdr mutex.", NULL);
        goto out;
    }

    bundleLen = zco_source_data_length(sdr, dlv.adu);
    log_info("bp_recv_once: Received bundle length: %d", bundleLen);
    *payload = malloc(bundleLen);
    if (!*payload) {
        log_error("bp_recv_once: Failed to allocate memory for payload.");
        sdr_exit_xn(sdr);
        bp_release_delivery(&dlv, 1);
        goto out;
    }
    zco_start_receiving(dlv.adu, &reader);
    CHKZERO(sdr_begin_xn(sdr));
    rc = zco_receive_source(sdr, &reader, bundleLen, *payload);
    log_info("bp_recv_once: Received %d bytes from ZCO.", rc);
    if (sdr_end_xn(sdr) < 0 || rc < 0) putErrmsg("Can't receive payload.", NULL);
    pthread_mutex_unlock(&sdrmutex);
    bp_release_delivery(&dlv, 1);

    // sap = bp_sap_registry_find(nodeNbr, service_id);
    // if (sap == NULL) {
    //     log_error("bp_recv_once: BpSAP is NULL for node_id=%d service_id=%d", nodeNbr,
    //     service_id); return -1;
    // }
    // log_info("BpSAP content: %p", sap);

out:
    bp_close(sap);
    return rc;
}

void bp_cancel_recv_once(uint32_t node_id, uint32_t service_id) {
    BpSAP sap = bp_sap_registry_find(node_id, service_id);
    Sdr sdr = getIonsdr();
    if (sap == NULL) {
        log_error("bp_interrupt: BpSAP is NULL");
        return;
    }

    bp_interrupt(sap);
}
