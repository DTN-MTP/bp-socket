#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../include/bp_socket.h"
#include "bp_genl_handlers.h"
#include "daemon.h"
#include "ion.h"
#include "log.h"

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs) {
    if (!attrs[BP_GENL_A_SOCKID] || !attrs[BP_GENL_A_PAYLOAD] || !attrs[BP_GENL_A_EID]) {
        log_error("Missing attribute(s) in SEND_BUNDLE");
        return NL_SKIP;
    }

    unsigned long sockid = nla_get_u64(attrs[BP_GENL_A_SOCKID]);
    char *payload = nla_get_string(attrs[BP_GENL_A_PAYLOAD]);
    int payload_size = strlen(payload) + 1;
    char *eid = nla_get_string(attrs[BP_GENL_A_EID]);
    int eid_size = strlen(eid) + 1;

    log_info("SEND_BUNDLE: socket ID %lu", sockid);
    return bp_send_to_eid(payload, payload_size, eid, eid_size);
}
int handle_request_bundle(Daemon *daemon, struct nlattr **attrs) {
    if (!attrs[BP_GENL_A_SERVICE_ID]) {
        log_error("Missing BP_GENL_A_SERVICE_ID in REQUEST_BUNDLE");
        return NL_SKIP;
    }

    uint32_t service_id = nla_get_u32(attrs[BP_GENL_A_SERVICE_ID]);
    log_info("REQUEST_BUNDLE: Bundle request initiated (service ID %u)", service_id);

    struct thread_args *args = malloc(sizeof(struct thread_args));
    if (!args) {
        log_error("Failed to allocate thread arguments");
        return -ENOMEM;
    }

    args->service_id = service_id;
    args->netlink_sock = daemon->genl_bp_sock;
    args->netlink_family = daemon->genl_bp_family_id;

    pthread_t thread;
    if (pthread_create(&thread, NULL, bp_recv_thread, args) != 0) {
        log_error("Failed to create thread");
        free(args);
        return -1;
    }

    pthread_detach(thread);

    return 0;
}

void *bp_recv_thread(void *arg) {
    struct thread_args *args = (struct thread_args *)arg;
    handle_deliver_bundle(args);
    free(args);
    return NULL;
}

int handle_deliver_bundle(struct thread_args *args) {
    char *payload = bp_recv_once(args->service_id);
    if (!payload) {
        log_error("DELIVER_BUNDLE: No payload received (service ID %u)", args->service_id);
        return -1;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        log_error("DELIVER_BUNDLE: Failed to allocate Netlink msg");
        free(payload);
        return -ENOMEM;
    }

    void *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, args->netlink_family, 0, 0,
                            BP_GENL_CMD_DELIVER_BUNDLE, BP_GENL_VERSION);
    if (!hdr || nla_put_u32(msg, BP_GENL_A_SERVICE_ID, args->service_id) < 0 ||
        nla_put_string(msg, BP_GENL_A_PAYLOAD, payload) < 0) {
        log_error("DELIVER_BUNDLE: Failed to construct Netlink reply");
        nlmsg_free(msg);
        free(payload);
        return -EMSGSIZE;
    }

    int err = nl_send_auto(args->netlink_sock, msg);
    nlmsg_free(msg);
    free(payload);

    if (err < 0) {
        log_error("DELIVER_BUNDLE: Failed to send Netlink message (service ID %u)",
                  args->service_id);
        return err;
    }

    log_info("DELIVER_BUNDLE: Bundle successfully delivered (service ID %u)", args->service_id);
    return 0;
}