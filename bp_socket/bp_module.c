#include "../include/bp_socket.h"
#include "af_bp.h"
#include "bp_genl.h"
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/semaphore.h>
#include <linux/socket.h>
#include <linux/uaccess.h>
#include <net/genetlink.h>
#include <net/sock.h>

static int __init bp_init(void)
{
	int ret;
	int rc;

	pr_info("bp_init: initializing module\n");

	/* generic netlink */
	ret = genl_register_family(&genl_fam);
	if (unlikely(ret)) {
		pr_crit("bp_init: failed to register generic netlink family\n");
		return ret;
	}

	/* protocol */
	rc = proto_register(&bp_proto, 0);
	if (rc) {
		pr_err("bp_init: failed to register proto\n");
		return rc;
	}

	rc = sock_register(&bp_family_ops);
	if (rc) {
		pr_err("bp_init: failed to register socket family\n");
		proto_unregister(&bp_proto);
		return rc;
	}

	pr_info("bp_init: module initialized successfully\n");
	return 0;
}

static void __exit bp_exit(void)
{
	pr_info("bp_exit: unloading module\n");
	sock_unregister(AF_BP);
	proto_unregister(&bp_proto);

	if (unlikely(genl_unregister_family(&genl_fam))) {
		pr_err(
		    "bp_init: failed to unregister generic netlink family\n");
		return;
	}

	pr_info("bp_exit: module unloaded successfully\n");
}

module_init(bp_init);
module_exit(bp_exit);

// Module metadata
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Custom socket protocol module");