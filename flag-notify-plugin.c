/*
   flag mail notification plugin for Dovecot

   flag notify Project

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dovecot/config.h>
#include <dovecot/lib.h>
#include <dovecot/compat.h>
#include <dovecot/llist.h>
#include <dovecot/mail-user.h>
#include <dovecot/mail-storage-hooks.h>
#include <dovecot/mail-storage.h>
#include <dovecot/mail-storage-private.h>
#include <dovecot/module-context.h>
#include <dovecot/notify-plugin.h>

#include <mapistore/mapistore.h>
#include <mapistore/mapistore_errors.h>

#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>

#ifndef __BEGIN_DECLS
#ifdef	__cplusplus
#define	__BEGIN_DECLS	extern "C" {
#define	__END_DECLS	}
#else
#define	__BEGIN_DECLS
#define	__END_DECLS
#endif
#endif

#define	flag_notify_USER_CONTEXT(obj) MODULE_CONTEXT(obj, flag_notify_user_module)

const char		*flag_notify_plugin_version = DOVECOT_ABI_VERSION;
const char	*flag_notify_plugin_dependencies[] = { "notify", NULL };
struct notify_context	*flag_notify_ctx;

enum flag_notify_field {
	flag_notify_FIELD_UID		= 0x1,
	flag_notify_FIELD_BOX		= 0x2,
	flag_notify_FIELD_MSGID		= 0x4,
	flag_notify_FIELD_PSIZE		= 0x8,
	flag_notify_FIELD_VSIZE		= 0x10,
	flag_notify_FIELD_FLAGS		= 0x20,
	flag_notify_FIELD_FROM		= 0x40,
	flag_notify_FIELD_SUBJECT	= 0x80
};

#define	flag_notify_DEFAULT_FIELDS \
	(flag_notify_FIELD_UID | flag_notify_FIELD_BOX | \
	 flag_notify_FIELD_MSGID | flag_notify_FIELD_PSIZE)

enum flag_notify_event {
	flag_notify_EVENT_DELETE		= 0x1,
	flag_notify_EVENT_UNDELETE	= 0x2,
	flag_notify_EVENT_EXPUNGE	= 0x4,
	flag_notify_EVENT_SAVE		= 0x8,
	flag_notify_EVENT_COPY		= 0x10,
	flag_notify_EVENT_MAILBOX_CREATE	= 0x20,
	flag_notify_EVENT_MAILBOX_DELETE	= 0x40,
	flag_notify_EVENT_MAILBOX_RENAME	= 0x80,
	flag_notify_EVENT_FLAG_CHANGE	= 0x100
};

#define	flag_notify_DEFAULT_EVENTS	(flag_notify_EVENT_SAVE)

struct flag_notify_user {
	union mail_user_module_context	module_ctx;
	enum flag_notify_field		fields;
	enum flag_notify_event		events;
	const char			*resolver;
	const char			*username;
	const char			*backend;
};

struct flag_notify_message {
	struct flag_notify_message	*prev;
	struct flag_notify_message	*next;
	enum flag_notify_event		event;
	uint32_t			uid;
	char				sep;
	const char			*destination_folder;
};

struct flag_notify_mail_txn_context {
	pool_t				pool;
	struct mail_namespace		*ns;
	char				sep;
	struct flag_notify_message	*messages;
	struct flag_notify_message	*messages_tail;
};

__BEGIN_DECLS

void flag_notify_plugin_init(struct module *);
void flag_notify_plugin_deinit(void);
enum mapistore_error mapistore_notification_init(TALLOC_CTX *, struct loadparm_context *,
						 struct mapistore_notification_context **);

__END_DECLS

static MODULE_CONTEXT_DEFINE_INIT(flag_notify_user_module, &mail_user_module_register);

static void flag_notify_mail_user_created(struct mail_user *user)
{
	struct flag_notify_user	*ocuser;
	const char		*str;
	char			*aux;

	ocuser = p_new(user->pool, struct flag_notify_user, 1);
	MODULE_CONTEXT_SET(user, flag_notify_user_module, ocuser);

	ocuser->fields = flag_notify_DEFAULT_FIELDS;
	ocuser->events = flag_notify_DEFAULT_EVENTS;

	str = mail_user_plugin_getenv(user, "flag_notify_resolver");
	if (str == NULL) {
		ocuser->resolver = NULL;
	} else {
		ocuser->resolver = i_strdup(str);
	}

	str = mail_user_plugin_getenv(user, "flag_notify_cn");
	if ((str == NULL) || !strcmp(str, "username")) {
		aux = i_strdup(user->username);
		ocuser->username = i_strdup(strtok(aux, "@"));
		free(aux);
	} else if (str && !strcmp(str, "email")) {
		ocuser->username = i_strdup(user->username);
	} else {
		i_fatal("Invalid flag_notify_cn parameter in dovecot.conf");
	}

	str = mail_user_plugin_getenv(user, "flag_notify_backend");
	if (str == NULL) {
		ocuser->backend = i_strdup("sogo");
	} else {
		ocuser->backend = i_strdup(str);
	}
}

static void flag_notify_append_mail_message(struct flag_notify_mail_txn_context *ctx,
					   struct mail *mail, enum flag_notify_event event)
{
	struct flag_notify_message		*msg;

	msg = p_new(ctx->pool, struct flag_notify_message, 1);
	msg->event = event;
	msg->uid = 0;
	msg->sep = ctx->sep;
	msg->destination_folder = p_strdup(ctx->pool, mailbox_get_name(mail->box));
	DLLIST2_APPEND(&ctx->messages, &ctx->messages_tail, msg);
}
static void flag_notify_mail_save(void *txn, struct mail *mail)
{
	struct flag_notify_mail_txn_context	*ctx;

	ctx = (struct flag_notify_mail_txn_context *) txn;
	flag_notify_append_mail_message(ctx, mail, flag_notify_EVENT_SAVE);
}

static void flag_notify_mail_copy(void *txn, struct mail *src, struct mail *dst)
{
	struct flag_notify_mail_txn_context	*ctx;

	ctx = (struct flag_notify_mail_txn_context *) txn;
	flag_notify_append_mail_message(ctx, dst, flag_notify_EVENT_COPY);
}

static void *flag_notify_mail_transaction_begin(struct mailbox_transaction_context *t)
{
	struct flag_notify_mail_txn_context	*ctx;
	pool_t					pool;

	pool = pool_alloconly_create("flag_notify", 2048);
	ctx = p_new(pool, struct flag_notify_mail_txn_context, 1);
	ctx->pool = pool;
	ctx->ns = mailbox_get_namespace(t->box);
	ctx->sep = mailbox_list_get_hierarchy_sep(t->box->list);

	return ctx;
}


static bool flag_notify_newmail(struct flag_notify_user *user,
			       const struct flag_notify_message *msg)
{
	TALLOC_CTX				*mem_ctx;
	enum mapistore_error			retval;
	struct loadparm_context			*lp_ctx;
	struct mapistore_context		mstore_ctx;
	struct mapistore_notification_context	*ctx;
	bool					bret;
	int					ret = false;
	int					rc;
	int					sock;
	int					endpoint;
	int					timeout;
	int					i;
	int					bytes;
	uint32_t				count = 0;
	const char				**hosts = NULL;
	char					*data = NULL;
	uint8_t					*blob = NULL;
	size_t					msglen;

	mem_ctx = talloc_new(NULL);
	if (!mem_ctx) {
		i_debug("unable to initialize memory context");
		return false;
	}

	lp_ctx = loadparm_init_global(true);
	if (!lp_ctx) {
		i_debug("unable to load global parameters");
		talloc_free(mem_ctx);
		return false;
	}

	data = talloc_asprintf(mem_ctx, "%d.eml", msg->uid);
	if (!data) {
		i_debug("unable to allocate memory");
		goto end;
	}

	retval = mapistore_notification_payload_newmail(mem_ctx, (char *) user->backend, data, (char *) msg->destination_folder,
							msg->sep, &blob, &msglen);
	talloc_free(data);
	if (retval) {
		i_debug("unable to generate newmail payload for user %s with msg uid=%d",
			user->username, msg->uid);
		goto end;
	}

	/* initialize mapistore notification */
	if (user->resolver) {
		bret = lpcfg_set_cmdline(lp_ctx, "mapistore:notification_cache", user->resolver);
		if (bret == false) {
			i_fatal("unable to set resolver address '%s'", user->resolver);
		}
	}
	retval = mapistore_notification_init(mem_ctx, lp_ctx, &ctx);
	if (retval != MAPISTORE_SUCCESS) {
		i_debug("unable to initialize mapistore notification");
		goto end;
	}
	mstore_ctx.notification_ctx = ctx;

	/* Check if the user is registered */
	retval = mapistore_notification_resolver_exist(&mstore_ctx, user->username);
	if (retval) {
		i_debug("resolver: %s", mapistore_errstr(retval));
		goto end;
	}

	/* Retrieve server instances */
	retval = mapistore_notification_resolver_get(mem_ctx, &mstore_ctx, user->username,
						     &count, &hosts);
	if (retval) {
		i_debug("resolver record: %s", mapistore_errstr(retval));
		goto end;
	}

	/* Create socket with super powers */
	sock = nn_socket(AF_SP, NN_PUSH);
	if (sock < 0) {
		i_debug("unable to create socket");
		return false;
	}

	timeout = 200;
	rc = nn_setsockopt(sock, NN_SOL_SOCKET, NN_SNDTIMEO, &timeout, sizeof(timeout));
	if (rc < 0) {
		i_debug("unable to set timeout on socket send");
		goto end;
	}

	for (i = 0; i < count; i++) {
		endpoint = nn_connect(sock, hosts[i]);
		if (endpoint < 0) {
			oc_log(OC_LOG_ERROR, "unable to connect to %s", hosts[i]);
			continue;
		}
		bytes = nn_send(sock, (char *)blob, msglen, 0);
		if (bytes != msglen) {
			i_debug("Error sending msg: %d sent but %zu expected", bytes, msglen);
		}
		nn_shutdown(sock, endpoint);
	}

	ret = true;
end:
	talloc_free(lp_ctx);
	talloc_free(mem_ctx);
	return ret;
}

static void flag_notify_mail_transaction_commit(void *txn, struct mail_transaction_commit_changes *changes)
{
	struct flag_notify_mail_txn_context	*ctx;
	struct flag_notify_message		*msg;
	struct flag_notify_user			*user;
	struct seq_range_iter			iter;
	uint32_t				uid;
	int					rc;
	unsigned int				n = 0;

	ctx = (struct flag_notify_mail_txn_context *)txn;
	user = flag_notify_USER_CONTEXT(ctx->ns->user);

	seq_range_array_iter_init(&iter, &changes->saved_uids);
	for (msg = ctx->messages; msg != NULL; msg = msg->next) {
		if (msg->event == flag_notify_EVENT_COPY ||
		    msg->event == flag_notify_EVENT_SAVE) {
			if (seq_range_array_iter_nth(&iter, n++, &uid)) {
				msg->uid = uid;
				flag_notify_newmail(user, msg);
			}
		}
	}

	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));
	pool_unref(&ctx->pool);
}


static void flag_notify_mail_transaction_rollback(void *txn)
{
	struct flag_notify_mail_txn_context	*ctx;

	ctx = (struct flag_notify_mail_txn_context *)txn;
	pool_unref(&ctx->pool);
}


static const struct notify_vfuncs flag_notify_vfuncs = {
	.mail_save = flag_notify_mail_save,
	.mail_copy = flag_notify_mail_copy,
	.mail_transaction_begin = flag_notify_mail_transaction_begin,
	.mail_transaction_commit = flag_notify_mail_transaction_commit,
	.mail_transaction_rollback = flag_notify_mail_transaction_rollback
};

static struct mail_storage_hooks flag_notify_storage_hooks = {
	.mail_user_created = flag_notify_mail_user_created
};

void flag_notify_plugin_init(struct module *module)
{
	i_debug("flag_notify_plugin_init");
	flag_notify_ctx = notify_register(&flag_notify_vfuncs);
	mail_storage_hooks_add(module, &flag_notify_storage_hooks);
}


void flag_notify_plugin_deinit(void)
{
	i_debug("flag_notify_plugin_deinit");
	mail_storage_hooks_remove(&flag_notify_storage_hooks);
	notify_unregister(flag_notify_ctx);
}
