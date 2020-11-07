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
 * Sean Hansen <seanmhansen7@gmail.com>
 *
 * mod_newrelic.c -- New Relic reporting module
 * This module reports call/RTP statistics to New Relic APM
 *
 */
#include <switch.h>
#include <libnewrelic.h>

/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_newrelic_shutdown);
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
	uint32_t stats_task_id;
	switch_event_node_t *node;
	switch_memory_pool_t *pool;
	newrelic_app_config_t *config;
	newrelic_app_t *app;
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
	globals.stats_task_id = -1;

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

	txn = newrelic_start_non_web_transaction(globals.app, "FreeSWITCHHangupTxn");
	seg = newrelic_start_segment(txn, NULL, NULL);

	custom_event = newrelic_create_custom_event("FreeSWITCHHangupEvent");

	channel = switch_core_session_get_channel(session);
	switch_channel_get_variables(channel, &event);

	for (switch_event_header_t *h = event->headers; h; h = h->next) {
		if (!strcasecmp(h->name, "rtp_audio_in_skip_packet_count")) {
			newrelic_custom_event_add_attribute_long(custom_event, "SkipPacketCount", atol(h->value));
		} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_packet_count")) {
			newrelic_custom_event_add_attribute_long(custom_event, "JitterPacketCount", atol(h->value));
		} else if (!strcasecmp(h->name, "rtp_audio_in_dtmf_packet_count")) {
			newrelic_custom_event_add_attribute_long(custom_event, "DTMFPacketCount", atol(h->value));
		} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_min_variance")) {
			newrelic_custom_event_add_attribute_double(custom_event, "JitterMinVariance", strtod(h->value, NULL));
		} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_max_variance")) {
			newrelic_custom_event_add_attribute_double(custom_event, "JitterMaxVariance", strtod(h->value, NULL));
		} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_loss_rate")) {
			newrelic_custom_event_add_attribute_double(custom_event, "JitterLossRate", strtod(h->value, NULL));
		} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_burst_rate")) {
			newrelic_custom_event_add_attribute_double(custom_event, "JitterBurstRate", strtod(h->value, NULL));
		} else if (!strcasecmp(h->name, "rtp_audio_in_mean_interval")) {
			newrelic_custom_event_add_attribute_double(custom_event, "MeanInterval", strtod(h->value, NULL));
		} else if (!strcasecmp(h->name, "rtp_audio_in_flaw_total")) {
			newrelic_custom_event_add_attribute_long(custom_event, "FlawTotal", atol(h->value));
		} else if (!strcasecmp(h->name, "rtp_audio_in_mos")) {
			newrelic_custom_event_add_attribute_double(custom_event, "Mos", strtod(h->value, NULL));
		} else if (!strcasecmp(h->name, "sip_from_host")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipFromHost", h->value);
		} else if (!strcasecmp(h->name, "sip_contact_user")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipContactUser", h->value);
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
			newrelic_custom_event_add_attribute_int(custom_event, "SipTermStatus", atoi(h->value));
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
		} else if (!strcasecmp(h->name, "sip_to_user")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipToUser", h->value);
		} else if (!strcasecmp(h->name, "sip_from_user")) {
			newrelic_custom_event_add_attribute_string(custom_event, "SipFromUser", h->value);
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

SWITCH_STANDARD_SCHED_FUNC(stats_callback)
{
	switch_console_callback_match_t *callback = NULL;
	newrelic_segment_t* seg = 0;
	newrelic_txn_t* txn = 0;

	if (!(callback = switch_core_session_findall())) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "No sessions found, re-scheduling\n");
	} else {
		txn = newrelic_start_non_web_transaction(globals.app, "FreeSWITCHStatsTxn");
		seg = newrelic_start_segment(txn, NULL, NULL);

		for (switch_console_callback_match_node_t *m = callback->head; m; m = m->next) {
			switch_core_session_t *session = NULL;

			if((session = switch_core_session_locate(m->val))) {
				switch_channel_t *channel = NULL;
				switch_event_t *event = NULL;
				newrelic_custom_event_t* custom_event = 0;

				custom_event = newrelic_create_custom_event("FreeSWITCHStatsEvent");

				switch_core_media_set_stats(session);
				switch_core_session_rwunlock(session);

				channel = switch_core_session_get_channel(session);
				switch_channel_get_variables(channel, &event);

				for (switch_event_header_t *h = event->headers; h; h = h->next) {
					if (!strcasecmp(h->name, "rtp_audio_in_skip_packet_count")) {
						newrelic_custom_event_add_attribute_long(custom_event, "SkipPacketCount", atol(h->value));
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_packet_count")) {
						newrelic_custom_event_add_attribute_long(custom_event, "JitterPacketCount", atol(h->value));
					} else if (!strcasecmp(h->name, "rtp_audio_in_dtmf_packet_count")) {
						newrelic_custom_event_add_attribute_long(custom_event, "DTMFPacketCount", atol(h->value));
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_min_variance")) {
						newrelic_custom_event_add_attribute_double(custom_event, "JitterMinVariance", strtod(h->value, NULL));
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_max_variance")) {
						newrelic_custom_event_add_attribute_double(custom_event, "JitterMaxVariance", strtod(h->value, NULL));
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_loss_rate")) {
						newrelic_custom_event_add_attribute_double(custom_event, "JitterLossRate", strtod(h->value, NULL));
					} else if (!strcasecmp(h->name, "rtp_audio_in_jitter_burst_rate")) {
						newrelic_custom_event_add_attribute_double(custom_event, "JitterBurstRate", strtod(h->value, NULL));
					} else if (!strcasecmp(h->name, "rtp_audio_in_mean_interval")) {
						newrelic_custom_event_add_attribute_double(custom_event, "MeanInterval", strtod(h->value, NULL));
					} else if (!strcasecmp(h->name, "rtp_audio_in_flaw_total")) {
						newrelic_custom_event_add_attribute_long(custom_event, "FlawTotal", atol(h->value));
					} else if (!strcasecmp(h->name, "rtp_audio_in_mos")) {
						newrelic_custom_event_add_attribute_double(custom_event, "Mos", strtod(h->value, NULL));
					} else if (!strcasecmp(h->name, "sofia_profile_name")) {
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
						newrelic_custom_event_add_attribute_string(custom_event, "SipFromUser", h->value);
					} else if (!strcasecmp(h->name, "sip_contact_user")) {
						newrelic_custom_event_add_attribute_string(custom_event, "ContactUser", h->value);
					}
				}

				newrelic_record_custom_event(txn, &custom_event);
			}
		}

		newrelic_end_segment(txn, &seg);
		newrelic_end_transaction(&txn);
	}

	// Reschedule the task
	task->runtime = switch_epoch_time_now(NULL) + globals.rtp_scan_interval;
}

/* Macro expands to: switch_status_t mod_newrelic_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_newrelic_load)
{
	if (do_config(SWITCH_FALSE, pool) == SWITCH_STATUS_TERM) {
		// We were unable to parse the configuration or start the app
		return SWITCH_STATUS_TERM;
	}

	if (globals.report_rtp_stats) {
		//Schedule stats to be collected every rtp_scan_interval seconds
		globals.stats_task_id = switch_scheduler_add_task(switch_epoch_time_now(NULL), stats_callback, "newrelic_rtp_stats", "mod_newrelic", 0, NULL, SSHF_NONE | SSHF_OWN_THREAD);
	}

	switch_core_add_state_handler(&state_handlers);

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/* Called when the system shuts down
 * Macro expands to: switch_status_t mod_newrelic_shutdown()
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_newrelic_shutdown)
{
	if (globals.report_rtp_stats) {
		if (switch_scheduler_del_task_id(globals.stats_task_id) == 1) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Successfully terminated NewRelic stats task.\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Not sure if NewRelic stats task terminated!\n");
		}
	}

	if (globals.app != NULL) {
		newrelic_destroy_app(&globals.app);
	}

	switch_event_unbind(&globals.node);
	switch_core_remove_state_handler(&state_handlers);

	return SWITCH_STATUS_SUCCESS;
}
