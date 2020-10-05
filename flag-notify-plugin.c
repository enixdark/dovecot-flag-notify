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
#include <dovecot/str.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include "elastic.h"

#ifndef __BEGIN_DECLS
#ifdef	__cplusplus
#define	__BEGIN_DECLS	extern "C" {
#define	__END_DECLS	}
#else
#define	__BEGIN_DECLS
#define	__END_DECLS
#endif
#endif

#define	FLAG_NOTIFY_USER_CONTEXT(obj) MODULE_CONTEXT(obj, flag_notify_user_module)
const char		*flag_notify_plugin_version = DOVECOT_ABI_VERSION;
const char	*flag_notify_plugin_dependencies[] = { "notify", NULL };
struct notify_context	*flag_notify_ctx;

enum flag_notify_field {
	FLAG_NOTIFY_FIELD_UID		= 0x1,
	FLAG_NOTIFY_FIELD_BOX		= 0x2,
	FLAG_NOTIFY_FIELD_MSGID		= 0x4,
	FLAG_NOTIFY_FIELD_PSIZE		= 0x8,
	FLAG_NOTIFY_FIELD_VSIZE		= 0x10,
	FLAG_NOTIFY_FIELD_FLAGS		= 0x20,
	FLAG_NOTIFY_FIELD_FROM		= 0x40,
	FLAG_NOTIFY_FIELD_SUBJECT	= 0x80
};

#define	FLAG_NOTIFY_DEFAULT_FIELDS \
	(FLAG_NOTIFY_FIELD_UID | FLAG_NOTIFY_FIELD_BOX | \
	FLAG_NOTIFY_FIELD_MSGID | FLAG_NOTIFY_FIELD_PSIZE)

enum flag_notify_event {
	FLAG_NOTIFY_EVENT_DELETE		= 0x1,
	FLAG_NOTIFY_EVENT_UNDELETE	= 0x2,
	FLAG_NOTIFY_EVENT_EXPUNGE	= 0x4,
	FLAG_NOTIFY_EVENT_SAVE		= 0x8,
	FLAG_NOTIFY_EVENT_COPY		= 0x10,
	FLAG_NOTIFY_EVENT_MAILBOX_CREATE	= 0x20,
	FLAG_NOTIFY_EVENT_MAILBOX_DELETE	= 0x40,
	FLAG_NOTIFY_EVENT_MAILBOX_RENAME	= 0x80,
	FLAG_NOTIFY_EVENT_FLAG_CHANGE	= 0x100
};

#define FLAG_NOTIFY_DEFAULT_EVENTS	(FLAG_NOTIFY_EVENT_SAVE)

struct flag_notify_user {
	union mail_user_module_context	module_ctx;
	struct elastic_connection       *conn;
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

__END_DECLS

static MODULE_CONTEXT_DEFINE_INIT(flag_notify_user_module, &mail_user_module_register);

static void flag_notify_mail_user_created(struct mail_user *user)
{
	struct flag_notify_user	*ocuser;
	const char		*str;
	char			*aux;
	const char              *elastic;
	ocuser = p_new(user->pool, struct flag_notify_user, 1);
	MODULE_CONTEXT_SET(user, flag_notify_user_module, ocuser);

	ocuser->fields = FLAG_NOTIFY_DEFAULT_FIELDS;
	ocuser->events = FLAG_NOTIFY_DEFAULT_EVENTS;
        elastic = mail_user_plugin_getenv(user, "flag_notify_elastic");
	i_debug("\n ============= CREATED ========== \n%s", elastic);
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
        //struct flag_notify_user *user_test = MODULE_CONTEXT(user, flag_notify_user_module);
        //i_debug("\n ============= USER ========== %s\n", user_test->username);
	
	//struct fts_elastic_settings *s = i_new(struct fts_elastic_settings, 1);


	//struct elastic_connection *conn = NULL;
	//conn = i_new(struct elastic_connection, 1);
	//ocuser->conn = conn;
        //s->url = i_strdup(elastic);
        //i_debug("\n ============= USSSS ========== %s\n", s->url);
	//elastic_connection_init_new(s, &ocuser->conn);

	//i_debug("\n ESSSSSSSSSSSS %s\n", ocuser->conn->es_username);
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
	flag_notify_append_mail_message(ctx, mail, FLAG_NOTIFY_EVENT_SAVE);
}

static void flag_notify_mail_copy(void *txn, struct mail *src, struct mail *dst)
{
	struct flag_notify_mail_txn_context	*ctx;

	ctx = (struct flag_notify_mail_txn_context *) txn;
	flag_notify_append_mail_message(ctx, dst, FLAG_NOTIFY_EVENT_COPY);
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
	user = FLAG_NOTIFY_USER_CONTEXT(ctx->ns->user);
	seq_range_array_iter_init(&iter, &changes->saved_uids);
	for (msg = ctx->messages; msg != NULL; msg = msg->next) {
		if (msg->event == FLAG_NOTIFY_EVENT_COPY ||
		    msg->event == FLAG_NOTIFY_EVENT_SAVE) {
			if (seq_range_array_iter_nth(&iter, n++, &uid)) {
				msg->uid = uid;
				//flag_notify_newmail(user, msg);
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

static void mail_log_mail_update_flags(void *txn, struct mail *mail,
						       enum mail_flags old_flags)
{
	i_debug("\n CHANGE ============%d\n", old_flags);
   //struct mail_private *p = (struct mail_private *)mail;
   struct flag_notify_mail_txn_context	*ctx;
   struct flag_notify_user *user;;

   ctx = (struct flag_notify_mail_txn_context *)txn;
   user = FLAG_NOTIFY_USER_CONTEXT(ctx->ns->user);
   //char* t = p->v.get_keywords(mail);
   //string_t *text;
   //text = t_str_new(128);
   //imap_write_flags(text, mail_get_flags(mail),
   //                            mail_get_keywords(mail));
   //
   //char *t = c_str(mail_get_keywords(mail));
   string_t *text;
   text = t_str_new(128);
   imap_write_flags(text, mail_get_flags(mail),
                                 mail_get_keywords(mail));
   i_debug("\n keyword =========== %s\n", str_c(text));
   
   if(user->conn == NULL){
	const char *elastic;
	struct fts_elastic_settings *s = i_new(struct fts_elastic_settings, 1);
	struct elastic_connection *conn = NULL;
	conn = i_new(struct elastic_connection, 1);
        //user->conn = conn;
	elastic = mail_user_plugin_getenv(user, "flag_notify_elastic");
	s->url = i_strdup(elastic);
	elastic_connection_init_new(&s, &conn);
	i_debug("\n ============= CHANGE USER ========== %s\n", elastic);
   }
   
   
   //struct flag_notify_user *user_test = MODULE_CONTEXT(user, flag_notify_user_module);
   //i_debug("\n ============= CHANGE USER ========== %s\n", user->conn->es_username);
}

static const struct notify_vfuncs flag_notify_vfuncs = {
	.mail_save = flag_notify_mail_save,
	.mail_copy = flag_notify_mail_copy,
	.mail_update_flags = mail_log_mail_update_flags,
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
