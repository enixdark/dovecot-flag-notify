ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = 	$(LIBDOVECOT_INCLUDE) 		\
		$(LIBDOVECOT_STORAGE_INCLUDE) 	\
		$(LIBDOVECOT_IMAP_INCLUDE) 	\
		$(MAPISTORE_CFLAGS)		\
		$(NANOMSG_CFLAGS)

LIBS += $(MAPISTORE_LIBS) $(NANOMSG_LIBS)

flag_notify_moduledir = $(dovecot_moduledir)
flag_notify_module_LTLIBRARIES = lib90_flag_notify_plugin.la

lib90_flag_notify_plugin_la_LDFLAGS = -module -avoid-version -shared
lib90_flag_notify_plugin_la_SOURCES = flag-notify-plugin.c
