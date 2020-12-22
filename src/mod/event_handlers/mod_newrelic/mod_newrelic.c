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
#include <libnewrelic.h>

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
	int report_rtp_stats;
	uint32_t rtp_scan_interval;
	switch_thread_t *thread;
	switch_event_node_t *node;
	switch_memory_pool_t *pool;
	newrelic_app_config_t *config;
	newrelic_app_t *app;
	uint32_t shutdown;
} globals;

static switch_status_t do_config(switch_bool_t reload, switch_memory_pool_t *pool)
{
	char *cf = "newrelic.conf";
	switch_xml_t cfg, xml, settings, param;
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Loading New Relic configuration\n");
	
	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
	globals.app = NULL;
	globals.app_name = "";
	globals.license_key = "";
	globals.report_rtp_stats = SWITCH_FALSE;
	globals.rtp_scan_interval = 30;
	globals.pool = pool;
	globals.shutdown = 0;
	
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
			} else if (!strcasecmp(var, "license-key") && !zstr(val)) {
				globals.license_key = switch_core_strdup(globals.pool, val);
			} else if (!strcasecmp(var, "report-rtp-stats") && !zstr(val)) {
				globals.report_rtp_stats = switch_true(val);
			} else if (!strcasecmp(var, "rtp-scan-interval") && !zstr(val)) {
				globals.rtp_scan_interval = (uint32_t) atoi(val);
			}
		}
	}
	
	if (zstr(globals.app_name) || zstr(globals.license_key)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "You must provide an app name & license key!\n");
		switch_xml_free(xml);
		return SWITCH_STATUS_TERM;
	}
	
	// Create the New Relic app
	globals.config = newrelic_create_app_config(globals.app_name, globals.license_key);
	
	globals.config->transaction_tracer.threshold = NEWRELIC_THRESHOLD_IS_OVER_DURATION;
  globals.config->transaction_tracer.duration_us = 1;
	
	// Wait up to 10 seconds for the SDK to connect to the daemon
  globals.app = newrelic_create_app(globals.config, 10000);
  newrelic_destroy_app_config(&globals.config);
	
	switch_xml_free(xml);
	
	if (globals.app == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error creating new relic app!\n");
		return SWITCH_STATUS_TERM;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Succesfully loaded New Relic configuration\n");

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t my_on_hangup(switch_core_session_t *session)
{
	newrelic_custom_event_t *custom_event = 0;
	newrelic_segment_t *seg = 0;
	newrelic_txn_t *txn = 0;
	switch_event_t *event = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	
	if (globals.shutdown) {
		return SWITCH_STATUS_SUCCESS;
	}
	
	txn = newrelic_start_non_web_transaction(globals.app, "FreeSWITCHHangupTxn");
	seg = newrelic_start_segment(txn, NULL, NULL);
	
	custom_event = newrelic_create_custom_event("FreeSWITCHHangupEvent");
	
	channel = switch_core_session_get_channel(session);
	switch_channel_get_variables(channel, &event);
	
	for (switch_event_header_t *h = event->headers; h; h = h->next) {
		/*
		switch_log_printf(
				SWITCH_CHANNEL_LOG,
				SWITCH_LOG_INFO,
				"%s: %s\n",
				h->name, h->value);
		*/
		
		if (!strcasecmp(h->name, "sofia_profile_name")) {
			newrelic_custom_event_add_attribute_string(custom_event, "ProfileName", h->value);
		} else if (!strcasecmp(h->name, "sip_from_host")) {
			newrelic_custom_event_add_attribute_string(custom_event, "FromHost", h->value);
		} else if (!strcasecmp(h->name, "sip_contact_user")) {
			newrelic_custom_event_add_attribute_string(custom_event, "ContactUser", h->value);
		} else if (!strcasecmp(h->name, "read_codec")) {
			newrelic_custom_event_add_attribute_string(custom_event, "ReadCodec", h->value);
		} else if (!strcasecmp(h->name, "write_codec")) {
			newrelic_custom_event_add_attribute_string(custom_event, "WriteCodec", h->value);
		} else if (!strcasecmp(h->name, "hangup_cause")) {
			newrelic_custom_event_add_attribute_string(custom_event, "HangupCause", h->value);
		} else if (!strcasecmp(h->name, "sip_invite_failure_status")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipInviteFailureStatus", h->value);
		} else if (!strcasecmp(h->name, "sip_invite_failure_phrase")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipInviteFailurePhrase", h->value);
		} else if (!strcasecmp(h->name, "sip_user_agent")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipUserAgent", h->value);
		} else if (!strcasecmp(h->name, "sip_term_status")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipTermStatus", h->value);
		} else if (!strcasecmp(h->name, "sofia_profile_name")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SofiaProfileName", h->value);
		} else if (!strcasecmp(h->name, "direction")) {
			newrelic_custom_event_add_attribute_string(custom_event, "Direction", h->value);
		} else if (!strcasecmp(h->name, "sip_gateway_name")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipGatewayName", h->value);
		} else if (!strcasecmp(h->name, "remote_media_ip")) {
			newrelic_custom_event_add_attribute_string(custom_event, "RemoteMediaIp", h->value);
		} else if (!strcasecmp(h->name, "uuid")) {
			newrelic_custom_event_add_attribute_string(custom_event, "Uuid", h->value);
		}
	}
	
	newrelic_record_custom_event(txn, &custom_event);
	newrelic_end_segment(txn, &seg);
	newrelic_end_transaction(&txn);
	
	return SWITCH_STATUS_SUCCESS;
}

static switch_state_handler_table_t state_handlers = {
	/*.on_init */ NULL,
	/*.on_routing */ NULL,
	/*.on_execute */ NULL,
	/*.on_hangup */ my_on_hangup,
	/*.on_exchange_media */ NULL,
	/*.on_soft_execute */ NULL,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL,
	/*.on_reset */ NULL,
	/*.on_park */ NULL,
	/*.on_reporting */ NULL
};

static void *SWITCH_THREAD_FUNC stats_thread(switch_thread_t *t, void *obj)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "New Relic stats thread started.\n");

	while (!globals.shutdown) {
		switch_console_callback_match_t *callback = NULL;
		newrelic_custom_event_t* custom_event = 0;
  	newrelic_segment_t* seg = 0;
		newrelic_txn_t* txn = 0;
		
		int session_count = 0;
		
		long in_skip_packet_count = 0;
		long in_jitter_packet_count = 0;
		long in_dtmf_packet_count = 0;
		
		double in_tot_jitter_min_variance = 0;
		double in_tot_jitter_max_variance = 0;
		double in_tot_jitter_loss_rate = 0;
		double in_tot_jitter_burst_rate = 0;
		
		double in_avg_jitter_min_variance = 0;
		double in_avg_jitter_max_variance = 0;
		double in_avg_jitter_loss_rate = 0;
		double in_avg_jitter_burst_rate = 0;
		
		double in_tot_mean_interval = 0;
		double in_avg_mean_interval = 0;
		
		long in_flaw_total = 0;
		long in_avg_flaw_total = 0;
		
		double in_tot_mos = 0;
		double in_avg_mos = 0;
		
		if (!(callback = switch_core_session_findall())) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "No sessions found, sleeping\n");
			switch_sleep(globals.rtp_scan_interval * 1000000);
			continue;
		}
		
		txn = newrelic_start_non_web_transaction(globals.app, "FreeSWITCHStatsTxn");
		seg = newrelic_start_segment(txn, NULL, NULL);
		
		custom_event = newrelic_create_custom_event("FreeSWITCHStatsEvent");
		session_count = callback->count;
 
 		newrelic_custom_event_add_attribute_int(custom_event, "SessionCount", session_count);
 		
	  //newrelic_custom_event_add_attribute_int(custom_event, "keya", 42);
	  //newrelic_custom_event_add_attribute_long(custom_event, "keyb", 84);
	  //newrelic_custom_event_add_attribute_double(custom_event, "keyc", 42.42);
	  //newrelic_custom_event_add_attribute_string(custom_event, "keyd", "A string");
		
		for (switch_console_callback_match_node_t *m = callback->head; m; m = m->next) {
			switch_core_session_t *session = NULL;
			
			if((session = switch_core_session_locate(m->val))) {
				switch_channel_t *channel = NULL;
				switch_event_t *event = NULL;
				
				switch_core_media_set_stats(session);
				switch_core_session_rwunlock(session);
				
				channel = switch_core_session_get_channel(session);
				switch_channel_get_variables(channel, &event);
				
				for (switch_event_header_t *h = event->headers; h; h = h->next) {
					/*
					switch_log_printf(
							SWITCH_CHANNEL_LOG,
							SWITCH_LOG_CONSOLE,
							"%s: %s\n",
							h->name, h->value);
					*/
					
					if (!strcasecmp(h->name, "rtp_audio_in_skip_packet_count")) {
						in_skip_packet_count += atol(h->value);
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_packet_count")) {
						in_jitter_packet_count += atol(h->value);
					} else if (!strcasecmp(h->name, "rtp_audio_in_dtmf_packet_count")) {
						in_dtmf_packet_count += atol(h->value);
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_min_variance")) {
						in_tot_jitter_min_variance += strtod(h->value, NULL);
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_max_variance")) {
						in_tot_jitter_max_variance += strtod(h->value, NULL);
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_loss_rate")) {
						in_tot_jitter_loss_rate += strtod(h->value, NULL);
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_burst_rate")) {
						in_tot_jitter_burst_rate += strtod(h->value, NULL);
					} else if (!strcasecmp(h->name, "rtp_audio_in_mean_interval")) {
						in_tot_mean_interval += strtod(h->value, NULL);
					} else if (!strcasecmp(h->name, "rtp_audio_in_flaw_total")) {
						in_flaw_total += atol(h->value);
					} else if (!strcasecmp(h->name, "rtp_audio_in_mos")) {
						in_tot_mos += strtod(h->value, NULL);
					}
					/*
					else if (!strcasecmp(h->name, "sofia_profile_name")) {
						newrelic_custom_event_add_attribute_string(custom_event, "SofiaProfileName", h->value);
					} else if (!strcasecmp(h->name, "direction")) {
						newrelic_custom_event_add_attribute_string(custom_event, "Direction", h->value);
					} else if (!strcasecmp(h->name, "sip_gateway_name")) {
						newrelic_custom_event_add_attribute_string(custom_event, "SipGatewayName", h->value);
					} else if (!strcasecmp(h->name, "sip_gateway_name")) {
						newrelic_custom_event_add_attribute_string(custom_event, "SipGatewayName", h->value);
					} else if (!strcasecmp(h->name, "remote_media_ip")) {
						newrelic_custom_event_add_attribute_string(custom_event, "RemoteMediaIp", h->value);
					} else if (!strcasecmp(h->name, "uuid")) {
						newrelic_custom_event_add_attribute_string(custom_event, "Uuid", h->value);
					} else if (!strcasecmp(h->name, "sip_to_user")) {
						newrelic_custom_event_add_attribute_string(custom_event, "SipToUser", h->value);
					} else if (!strcasecmp(h->name, "sip_from_user")) {
						newrelic_custom_event_add_attribute_string(custom_event, "SipToUser", h->value);
					}
					*/
				}
			}
		}
		
		//Calculate averages
		in_avg_jitter_min_variance = in_tot_jitter_min_variance / (double)session_count;
		in_avg_jitter_max_variance = in_tot_jitter_max_variance / (double)session_count;
		in_avg_jitter_loss_rate = in_tot_jitter_loss_rate / (double)session_count;
		in_avg_jitter_burst_rate = in_tot_jitter_burst_rate / (double)session_count;
		
		in_avg_mean_interval = in_tot_mean_interval / (double)session_count;
		in_avg_flaw_total = in_flaw_total / (long)session_count;
		in_avg_mos = in_tot_mos / (double)session_count;
		
		newrelic_custom_event_add_attribute_long(custom_event, "SkipPacketCount", in_skip_packet_count);
		newrelic_custom_event_add_attribute_long(custom_event, "JitterPacketCount", in_jitter_packet_count);
		newrelic_custom_event_add_attribute_long(custom_event, "DTMFPacketCount", in_dtmf_packet_count);
		newrelic_custom_event_add_attribute_double(custom_event, "AvgJitterMinVariance", in_avg_jitter_min_variance);
		newrelic_custom_event_add_attribute_double(custom_event, "AvgJitterMaxVariance", in_avg_jitter_max_variance);
		newrelic_custom_event_add_attribute_double(custom_event, "AvgJitterLossRate", in_avg_jitter_loss_rate);
		newrelic_custom_event_add_attribute_double(custom_event, "AvgJitterBurstRate", in_avg_jitter_burst_rate);
		newrelic_custom_event_add_attribute_double(custom_event, "AvgMeanInterval", in_avg_mean_interval);
		
		newrelic_custom_event_add_attribute_long(custom_event, "AvgFlawTotal", in_avg_flaw_total);
		newrelic_custom_event_add_attribute_long(custom_event, "FlawTotal", in_flaw_total);
		
		newrelic_custom_event_add_attribute_double(custom_event, "AvgMos", in_avg_mos);
		
		newrelic_record_custom_event(txn, &custom_event);
		newrelic_end_segment(txn, &seg);
		newrelic_end_transaction(&txn);
		
		switch_sleep(30000000);
	}

	return NULL;
}

/* Macro expands to: switch_status_t mod_newrelic_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_newrelic_load)
{
	switch_threadattr_t *thd_attr;

	if (do_config(SWITCH_FALSE, pool) == SWITCH_STATUS_TERM) {
		// We were unable to parse the configuration or start the app
		return SWITCH_STATUS_TERM;
	}
	
	if (globals.report_rtp_stats) {
		switch_threadattr_create(&thd_attr, globals.pool);
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&globals.thread, thd_attr, stats_thread, NULL, globals.pool);
	}
	
	switch_core_add_state_handler(&state_handlers);
	
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_newrelic_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_newrelic_shutdown)
{
	switch_status_t status;
	
	globals.shutdown = 1;
	
	if (globals.report_rtp_stats) {
		switch_thread_join(&status, globals.thread);
	}
	
	if (globals.app != NULL) {
		newrelic_destroy_app(&globals.app);
	}
	
	switch_event_unbind(&globals.node);
	switch_core_remove_state_handler(&state_handlers);
	
	return SWITCH_STATUS_SUCCESS;
}
