/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 * Neal Horman <neal at wanlink dot com>
 *
 *
 * mod_newrelic.c -- Framework Demo Module
 *
 */
#include <switch.h>
// #include "libnewrelic.h"

/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_newrelic_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_newrelic_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_newrelic_load);

/* SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime)
 * Defines a switch_loadable_module_function_table_t and a static const char[] modname
 */
SWITCH_MODULE_DEFINITION(mod_newrelic, mod_newrelic_load, mod_newrelic_shutdown, NULL);

static struct {
	char *app_name;
	char *license_key;
	newrelic_app_config_t *config = 0;
	newrelic_app_t *app = 0;
	uint32_t shutdown = 0;
} globals;

static switch_state_handler_table_t state_handlers = {
	/*.on_init */ NULL,
	/*.on_routing */ NULL,
	/*.on_execute */ NULL,
	/*.on_hangup */ NULL,
	/*.on_exchange_media */ NULL,
	/*.on_soft_execute */ NULL,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL,
	/*.on_reset */ NULL,
	/*.on_park */ NULL,
	/*.on_reporting */ NULL
};

static switch_status_t do_config(switch_bool_t reload)
{
	char *cf = "newrelic.conf";
	switch_xml_t cfg, xml, settings, param;
	memset(&globals, 0, sizeof(globals));
	
	globals.app_name = "";
	globals.license_key = "";
	globals.pool = pool;
	
	/* parse the config */
	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}
	
	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			
			if (!strcasecmp(var, "app-name") && !zstr(val)) {
				globals.app_name = switch_core_strdup(globals.pool, val);
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "New Relic app name required.\n", cf);
				return SWITCH_STATUS_TERM;
			}
			
			if (!strcasecmp(var, "license-key") && !zstr(val)) {
				globals.license_key = switch_core_strdup(globals.pool, val);
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "New Relic license key required.\n", cf);
				return SWITCH_STATUS_TERM;
			}
		}
	}
	
	/*
	// Create the New Relic app
	globals.config = newrelic_create_app_config(app_name, license_key);
 
  customize_config(&globals.config);
	
	globals.config->transaction_tracer.threshold = NEWRELIC_THRESHOLD_IS_OVER_DURATION;
  globals.config->transaction_tracer.duration_us = 1;
	
	// Wait up to 10 seconds for the SDK to connect to the daemon
  app = newrelic_create_app(globals.config, 10000);
  newrelic_destroy_app_config(&globals.config);
	// Log if unable to connect to daemon??
	*/
	
	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}


static void *SWITCH_THREAD_FUNC stats_thread(switch_thread_t *t, void *obj)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "New Relic stats thread started.\n");

	while (!globals.shutdown) {
		switch_console_callback_match_t *callback = NULL;
		
		if (!(callback = switch_core_session_findall())) {
			continue;
		}
		
		for (m = list->head; m; m = m->next) {
			switch_core_session_t *session = NULL;
			
			if((session = switch_core_session_locate(m->val))) {
				switch_core_media_set_stats(session);
				switch_core_session_rwunlock(session);
				
				switch_channel_t *channel = switch_core_session_get_channel(session);
				switch_event_t *event = NULL;
				
				switch_channel_get_variables(channel, &event);
				
				for (h = event->headers; h; h = h->next) {
					switch_log_printf(
							SWITCH_CHANNEL_LOG,
							SWITCH_LOG_CONSOLE,
							"%s: %s\n",
							h->name, h->value);
				}
			}
		}
		
		switch_sleep(30000)
	}

}

/* Macro expands to: switch_status_t mod_newrelic_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_newrelic_load)
{
	
	switch_api_interface_t *api_interface;
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Loading New Relic configuration!\n");

	do_config(SWITCH_FALSE);
	
	switch_threadattr_t *thd_attr;
	switch_threadattr_create(&thd_attr, globals.pool);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&globals.thread, thd_attr, stats_thread, NULL, globals.pool);
	
	switch_core_add_state_handler(&state_handlers);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_newrelic_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_newrelic_shutdown)
{
	globals.shutdown = 1;
	//newrelic_destroy_app(&app);
	return SWITCH_STATUS_SUCCESS;
}
