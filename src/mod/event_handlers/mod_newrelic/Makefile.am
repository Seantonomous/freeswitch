include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_newrelic

if HAS_NEWRELIC
mod_LTLIBRARIES = mod_newrelic.la
mod_newrelic_la_SOURCES  = mod_newrelic.c
mod_newrelic_la_CFLAGS   = $(AM_CFLAGS) $(NEWRELIC_CFLAGS)
mod_newrelic_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_newrelic_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(NEWRELIC_LIBS)
else
install: error
all: error
error:
	$(error You must have libnewrelic installed to build mod_newrelic)
endif
