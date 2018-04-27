/*
 * audit-validate.c -	Check audit events based on internal model of how
 * 			it should work
 * Copyright (c) 2014 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <libaudit.h>
#include <auparse.h>
#include "audit-llist.h"
#include "service.h"


static llist l;
static slist s;
static FILE *f = NULL;

/* command line params */
static int debug = 0;
const char *version = "0.1";

void usage(void)
{
	fprintf(stderr, "version: %s\n", version);
	fprintf(stderr,
		"usage: audit-validate [--stdin] [--debug] [-f file]\n");
}

static int daemon_started = 0, system_started = 0;
static int suspend_service_reporting = 0;
static char timestamp[48];

char *extract_timestamp(auparse_state_t *au)
{
	char m[16];
	const au_event_t *e = auparse_get_timestamp(au);
	struct tm *btm = localtime(&e->sec);
	strftime(timestamp, sizeof(timestamp), "%x %T", btm);
	snprintf(m, sizeof(m), ".%u:%lu", e->milli, e->serial);
	strcat(timestamp, m);

	return timestamp;
}

void close_sessions(void)
{
	list_clear(&l);
}

void close_services(void)
{
	slist_clear(&s);
}

void process_system(auparse_state_t *au)
{
	const char *status = NULL;
	int override = 0, type = auparse_get_type(au);
	const char *tname = audit_msg_type_to_name(type);
	if (type == AUDIT_SYSTEM_BOOT) {
		suspend_service_reporting = 0;
		if (system_started) {
			status = "crashed - no shutdown";
			override = 1;
			// Close out sessions, services
			close_sessions();
			close_services();
		} else {
			status = "started";
			system_started = 1;
		}
	} else if (type == AUDIT_SYSTEM_SHUTDOWN) {
		if (system_started) {
			status = "down";
			system_started = 0;
			// Close out sessions and services
			close_sessions();
			// FIXME: question, should services stop before or
			// after this event?
			close_services();
			suspend_service_reporting = 1;
		} else
			status = "not started?";
	} else if (type == AUDIT_SYSTEM_RUNLEVEL) {
		if (system_started)
			status = "normal";
		else
			status = "not started?";
	}
	if (debug || override)
		printf("%s\tsystem: %s\t%s\n", extract_timestamp(au), tname, status);
}

void print_services(void)
{
	slist_first(&s);
	do {
		if (s.cur)
			printf("%s\n", s.cur->str);
	} while (slist_next(&s));
}

void process_service(auparse_state_t *au)
{
	const char *status = NULL;
	int type = auparse_get_type(au);
	const char *tname = audit_msg_type_to_name(type);
	const char *sname = auparse_find_field(au, "comm");
	if (sname) {
		sname = auparse_interpret_field(au);
		if (type == AUDIT_SERVICE_START) {
			// FIXME: There is no way to identify instances
			// if a service has multiple pids.
			if (slist_add_if_uniq(&s, sname) == 0) {
				printf("%s service %s is already started\n",
					extract_timestamp(au), sname);
			}
			status = "starting";
		} else {
			if (slist_find(&s, sname) == 0) {
				if (suspend_service_reporting == 0)
				printf("%s service %s has no start record\n",
					extract_timestamp(au), sname);
				// print_services();
			} else
				slist_remove(&s);
			status = "stopping";
		}
	} else {
		printf("Malformed SERVICE_START: no comm field\n");
		return;
	} 
	if (debug)
		printf("%s\tservice: %s %s\n", extract_timestamp(au),
				tname, status);
}

void process_daemon(auparse_state_t *au)
{
	const char *status = NULL;
	int override = 0, type = auparse_get_type(au);
	const char *tname = audit_msg_type_to_name(type);
	if (type == AUDIT_DAEMON_START) {
		if (daemon_started) {
			status = "crashed";
			override = 1;
		} else {
			daemon_started = 1;
			status = "started";
		}
	} else if (type == AUDIT_DAEMON_END) {
		if (daemon_started) {
			daemon_started = 0;
			status = "stopped";
		} else
			status = "not started?";
	} else if (type == AUDIT_DAEMON_ABORT) {
		if (daemon_started) {
			daemon_started = 0;
			status = "stopped";
		} else
			status = "aborted";
	}
	if (debug || override)
		printf("%s\tdaemon: %s\t%s\n",  extract_timestamp(au),
						tname, status);
}

// Goals
// 1) confirm pam stack progression, detect spurious records
// cron: user_acct,cred_acq,login,user_start,cred_refr,cred_disp,user_end
// user: user_auth,user_acct,cred_acq,login,user_role_change,user_start,user_end
//  terminal is the same except login record has none, login has auid, after
//  that, the session can be matched.
// 2) create session on user_start, end on: user_end||user_logout||system_shutd
// 3) report crash when new login with same sid
// 4) 
void process_session(auparse_state_t *au)
{
	int type = auparse_get_type(au);
	const char *tname = audit_msg_type_to_name(type);
//	printf("session: %s\n", tname);
}

int main(int argc, char *argv[])
{
	int i, use_stdin = 0;
	char *file = NULL;
        auparse_state_t *au;

	setlocale (LC_ALL, "");
	for (i=1; i<argc; i++) {
		if (strcmp(argv[i], "-f") == 0) {
			if (use_stdin == 0) {
				i++;
				file = argv[i];
			} else {
				fprintf(stderr,"stdin already given\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--stdin") == 0) {
			if (file == NULL)
				use_stdin = 1;
			else {
				fprintf(stderr, "file already given\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--debug") == 0) {
			debug = 1;
		} else {
			usage();
			return 1;
		}
	}
	list_create(&l);
	slist_create(&s);

	// Search for successful user logins
	if (file)
		au = auparse_init(AUSOURCE_FILE, file);
	else if (use_stdin)
		au = auparse_init(AUSOURCE_FILE_POINTER, stdin);
	else {
		if (getuid()) {
			fprintf(stderr, "You probably need to be root for this to work\n");
		}
		au = auparse_init(AUSOURCE_LOGS, NULL);
	}
	if (au == NULL) {
		fprintf(stderr, "Error - %s\n", strerror(errno));
		goto error_exit_1;
	}

	// The theory: iterate though events
	// 1) when LOGIN is found, create a new session node
	// 2) if that session number exists, close out the old one
	// 3) when USER_LOGIN is found, update session node
	// 4) When USER_END is found update session node and close it out
	// 5) When BOOT record found make new record and check for previous
	// 6) If previous boot found, set status to crash and logout everyone
	// 7) When SHUTDOWN found, close out reboot record

	while (auparse_next_event(au) > 0) {
		// We will take advantage of the fact that all events
		// of interest are one record long
		int type = auparse_get_type(au);
		if (type < 0)
			continue;
		switch (type)
		{
			case AUDIT_SYSTEM_BOOT:
			case AUDIT_SYSTEM_RUNLEVEL:
			case AUDIT_SYSTEM_SHUTDOWN:
				process_system(au);
				break;
			case AUDIT_SERVICE_START:
			case AUDIT_SERVICE_STOP:
				process_service(au);
				break;
			case AUDIT_DAEMON_START:
			case AUDIT_DAEMON_END:
			case AUDIT_DAEMON_ABORT:
				process_daemon(au);
				break;
			case AUDIT_USER_AUTH:
			case AUDIT_USER_ACCT:
			case AUDIT_CRED_ACQ:
			case AUDIT_LOGIN:
			case AUDIT_USER_ROLE_CHANGE:
			case AUDIT_USER_START:
			case AUDIT_USER_LOGIN:
			case AUDIT_USER_END:
			case AUDIT_USER_LOGOUT:
			case AUDIT_CRED_DISP:
				process_session(au);
				break;
		}
	}
	auparse_destroy(au);

	// Now output the leftovers
/*	list_first(&l);
	do {
		lnode *cur = list_get_cur(&l);
	} while (list_next(&l)); */

	list_clear(&l);
	if (f)
		fclose(f);
	return 0;

error_exit_1:
	list_clear(&l);
	if (f)
		fclose(f);
	return 1;
}

