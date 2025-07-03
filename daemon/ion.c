#include "log.h"
#include "sdr.h"
#include <bp.h>
#include "ion.h"
#include <pthread.h>

static struct sap_node *sap_list = NULL;
static pthread_mutex_t sap_list_lock = PTHREAD_MUTEX_INITIALIZER;

void sap_list_add(BpSAP sap, uint32_t node_id, uint32_t service_id) {
    struct sap_node *node = calloc(1, sizeof(struct sap_node));
    node->sap = sap;
    node->node_id = node_id;
    node->service_id = service_id;

    pthread_mutex_lock(&sap_list_lock);
    node->next = sap_list;
    sap_list = node;
    pthread_mutex_unlock(&sap_list_lock);
}

void sap_list_remove(BpSAP sap) {
    pthread_mutex_lock(&sap_list_lock);

    struct sap_node **p = &sap_list;
    while (*p) {
        if ((*p)->sap == sap) {
            struct sap_node *to_delete = *p;
            *p = (*p)->next;
            free(to_delete);
            break;
        }
        p = &(*p)->next;
    }

    pthread_mutex_unlock(&sap_list_lock);
}

BpSAP sap_list_find(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_list_lock);

    struct sap_node *n = sap_list;
    while (n) {
        if (n->node_id == node_id && n->service_id == service_id) {
            pthread_mutex_unlock(&sap_list_lock);
            return n->sap;
        }
        n = n->next;
    }

    pthread_mutex_unlock(&sap_list_lock);
    return NULL;
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

BpIndResult bp_recv_once(int service_id, char **payload) {
    BpSAP txSap;
    BpDelivery dlv;
    Sdr sdr = getIonsdr();
    ZcoReader reader;
    char *eid = NULL;
    int eid_size;
    int nodeNbr = getOwnNodeNbr();
    vast len;

    eid_size = snprintf(NULL, 0, "ipn:%d.%d", nodeNbr, service_id) + 1;
    eid = malloc(eid_size);
    if (!eid) {
        log_error("Failed to allocate EID");
        return -1;
    }
    snprintf(eid, eid_size, "ipn:%d.%d", nodeNbr, service_id);

    if (bp_open(eid, &txSap) < 0 || txSap == NULL) {
        log_error("Failed to open source endpoint.");
        goto out;
    }

    sap_list_add(txSap, nodeNbr, service_id);

    if (bp_receive(txSap, &dlv, BP_BLOCKING) < 0) {
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
        goto out;

    default:
        log_error("bp_recv_once: unexpected result %d", dlv.result);
        goto out;
    }

out:
    sap_list_remove(txSap);
    if (eid) free(eid);
    bp_release_delivery(&dlv, 0);
    bp_close(txSap);

    return dlv.result;
}

void bp_cancel_recv_once(uint32_t node_id, uint32_t service_id) {
    BpSAP sap = sap_list_find(node_id, service_id);

    if (sap == NULL) {
        log_error("bp_interrupt: BpSAP is NULL");
        return;
    }

    bp_interrupt(sap);
}