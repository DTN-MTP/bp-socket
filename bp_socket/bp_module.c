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

	/* generic netlink */
	ret = genl_register_family(&genl_fam);
	if (unlikely(ret)) {
		pr_err("bp_init: failed to register generic netlink family\n");
		goto out;
	}

	/* protocol */
	ret = proto_register(&bp_proto, 0);
	if (ret) {
		pr_err("bp_init: failed to register proto\n");
		goto out;
	}

	ret = sock_register(&bp_family_ops);
	if (ret) {
		pr_err("bp_init: failed to register socket family\n");
		goto err_unreg_proto;
	}

	return 0;

err_unreg_proto:
	proto_unregister(&bp_proto);
out:
	pr_err("bp_init: module initialization failed\n");
	return ret;
}

static void __exit bp_exit(void)
{
	sock_unregister(AF_BP);
	proto_unregister(&bp_proto);

	if (unlikely(genl_unregister_family(&genl_fam))) {
		pr_err(
		    "bp_init: failed to unregister generic netlink family\n");
	}
}

module_init(bp_init);
module_exit(bp_exit);

// Module metadata
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sylvain Pierrot");
MODULE_DESCRIPTION("A socket family for the Bundle Protocol (BP)");