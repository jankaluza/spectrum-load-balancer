/**
 * Spectrum load balancer
 *
 * Copyright (C) 2009, Jan Kaluza <hanzz@soc.pidgin.im>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "component.h"
#include <sys/stat.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/wait.h>
#endif
#include "errno.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream> 

#include "configfile.h"

static gboolean nodaemon = FALSE;
static gchar *logfile = NULL;
static gchar *lock_file = NULL;
static gboolean ver = FALSE;

static GOptionEntry options_entries[] = {
	{ "nodaemon", 'n', 0, G_OPTION_ARG_NONE, &nodaemon, "Disable background daemon mode", NULL },
	{ "logfile", 'l', 0, G_OPTION_ARG_STRING, &logfile, "Set file to log", NULL },
	{ "pidfile", 'p', 0, G_OPTION_ARG_STRING, &lock_file, "File where to write transport PID", NULL },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &ver, "Shows Spectrum version", NULL },
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, "", NULL }
};

static void daemonize(const char *cwd) {
#ifndef WIN32
	pid_t pid, sid;
	FILE* lock_file_f;
	char process_pid[20];

	/* already a daemon */
	if ( getppid() == 1 ) return;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(1);
	}
	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {
		exit(0);
	}

	/* At this point we are executing as the child process */

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		exit(1);
	}

	/* Change the current working directory.  This prevents the current
		directory from being locked; hence not being able to remove it. */
	if ((chdir(cwd)) < 0) {
		exit(1);
	}
	
    /* write our pid into it & close the file. */
	lock_file_f = fopen(lock_file, "w+");
	if (lock_file_f == NULL) {
		std::cout << "EE cannot write to lock file " << lock_file << ". Exiting\n";
		exit(1);
    }
	sprintf(process_pid,"%d\n",getpid());
	fwrite(process_pid,1,strlen(process_pid),lock_file_f);
	fclose(lock_file_f);
	
	freopen( "/dev/null", "r", stdin);
#endif
}


static gboolean transportReconnect(gpointer data) {
	BalancerComponent::instance()->transportConnect();
	return FALSE;
}

static gboolean sendPing(gpointer data) {
// 	BalancerComponent::instance()->j->xmppPing(BalancerComponent::instance()->jid(), BalancerComponent::instance());
	return TRUE;
}

/*
 * Called by notifier when new data can be received from socket
 */
static gboolean transportDataReceived(GIOChannel *source, GIOCondition condition, gpointer data) {
	BalancerComponent::instance()->j->recv(1000);
	return TRUE;
}

BalancerComponent::BalancerComponent(const std::string &config) {
	m_pInstance = this;
	m_reconnectCount = 0;
	m_config = config;
	m_firstConnection = true;
	connectIO = NULL;

	bool loaded = true;

	if (!loadConfigFile(config))
		loaded = false;

	g_thread_init(NULL);

	j = new Component("jabber:component:accept", m_configuration.server, m_configuration.jid, m_configuration.password, m_configuration.port);

	m_loop = g_main_loop_new(NULL, FALSE);

	if (loaded) {
		j->registerConnectionListener(this);
		transportConnect();
		g_main_loop_run(m_loop);
	}
}

BalancerComponent::~BalancerComponent(){
	g_main_loop_quit(m_loop);
	g_main_loop_unref(m_loop);
	delete j;
}

void BalancerComponent::handleLog(LogLevel level, LogArea area, const std::string &message) {
// 	if (m_configuration.logAreas & LOG_AREA_XML) {
// 		if (area == LogAreaXmlIncoming)
// 			Log("XML IN", message);
// 		else
// 			Log("XML OUT", message);
// 	}
}

void BalancerComponent::onSessionCreateError(const Error *error) {
	Log("gloox", "sessionCreateError");
}

bool BalancerComponent::loadConfigFile(const std::string &config) {
	ConfigFile cfg(config.empty() ? m_config : config);
	Configuration c = cfg.getConfiguration();

	if (!c && !m_configuration)
		return false;
	if (c)
		m_configuration = c;

	if (logfile)
		m_configuration.logfile = std::string(logfile);
	
	if (!m_configuration.logfile.empty())
		Log_.setLogFile(m_configuration.logfile);

	if (!lock_file)
		lock_file = g_strdup(m_configuration.pid_f.c_str());
	
	return true;
}


void BalancerComponent::onConnect() {
	Log("gloox", "CONNECTED!");
	m_reconnectCount = 0;

	if (m_firstConnection) {
		m_firstConnection = false;
		g_timeout_add_seconds(60, &sendPing, this);
	}
}

void BalancerComponent::onDisconnect(ConnectionError e) {
	Log("gloox", "Disconnected from Jabber server !");
	switch (e) {
		case ConnNoError: Log("gloox", "Reason: No error"); break;
		case ConnStreamError: Log("gloox", "Reason: Stream error"); break;
		case ConnStreamVersionError: Log("gloox", "Reason: Stream version error"); break;
		case ConnStreamClosed: Log("gloox", "Reason: Stream closed"); break;
		case ConnProxyAuthRequired: Log("gloox", "Reason: Proxy auth required"); break;
		case ConnProxyAuthFailed: Log("gloox", "Reason: Proxy auth failed"); break;
		case ConnProxyNoSupportedAuth: Log("gloox", "Reason: Proxy no supported auth"); break;
		case ConnIoError: Log("gloox", "Reason: IO Error"); break;
		case ConnParseError: Log("gloox", "Reason: Parse error"); break;
		case ConnConnectionRefused: Log("gloox", "Reason: Connection refused"); break;
// 		case ConnSocketError: Log("gloox", "Reason: Socket error"); break;
		case ConnDnsError: Log("gloox", "Reason: DNS Error"); break;
		case ConnOutOfMemory: Log("gloox", "Reason: Out Of Memory"); break;
		case ConnNoSupportedAuth: Log("gloox", "Reason: No supported auth"); break;
		case ConnTlsFailed: Log("gloox", "Reason: Tls failed"); break;
		case ConnTlsNotAvailable: Log("gloox", "Reason: Tls not available"); break;
		case ConnCompressionFailed: Log("gloox", "Reason: Compression failed"); break;
// 		case ConnCompressionNotAvailable: Log("gloox", "Reason: Compression not available"); break;
		case ConnAuthenticationFailed: Log("gloox", "Reason: Authentication Failed"); break;
		case ConnUserDisconnected: Log("gloox", "Reason: User disconnected"); break;
		case ConnNotConnected: Log("gloox", "Reason: Not connected"); break;
	};

	switch (j->streamError()) {
		case StreamErrorBadFormat: Log("gloox", "Stream error: Bad format"); break;
		case StreamErrorBadNamespacePrefix: Log("gloox", "Stream error: Bad namespace prefix"); break;
		case StreamErrorConflict: Log("gloox", "Stream error: Conflict"); break;
		case StreamErrorConnectionTimeout: Log("gloox", "Stream error: Connection timeout"); break;
		case StreamErrorHostGone: Log("gloox", "Stream error: Host gone"); break;
		case StreamErrorHostUnknown: Log("gloox", "Stream error: Host unknown"); break;
		case StreamErrorImproperAddressing: Log("gloox", "Stream error: Improper addressing"); break;
		case StreamErrorInternalServerError: Log("gloox", "Stream error: Internal server error"); break;
		case StreamErrorInvalidFrom: Log("gloox", "Stream error: Invalid from"); break;
		case StreamErrorInvalidId: Log("gloox", "Stream error: Invalid ID"); break;
		case StreamErrorInvalidNamespace: Log("gloox", "Stream error: Invalid Namespace"); break;
		case StreamErrorInvalidXml: Log("gloox", "Stream error: Invalid XML"); break;
		case StreamErrorNotAuthorized: Log("gloox", "Stream error: Not Authorized"); break;
		case StreamErrorPolicyViolation: Log("gloox", "Stream error: Policy violation"); break;
		case StreamErrorRemoteConnectionFailed: Log("gloox", "Stream error: Remote connection failed"); break;
		case StreamErrorResourceConstraint: Log("gloox", "Stream error: Resource constraint"); break;
		case StreamErrorRestrictedXml: Log("gloox", "Stream error: Restricted XML"); break;
		case StreamErrorSeeOtherHost: Log("gloox", "Stream error: See other host"); break;
		case StreamErrorSystemShutdown: Log("gloox", "Stream error: System shutdown"); break;
		case StreamErrorUndefinedCondition: Log("gloox", "Stream error: Undefined Condition"); break;
		case StreamErrorUnsupportedEncoding: Log("gloox", "Stream error: Unsupported encoding"); break;
		case StreamErrorUnsupportedStanzaType: Log("gloox", "Stream error: Unsupported stanza type"); break;
		case StreamErrorUnsupportedVersion: Log("gloox", "Stream error: Unsupported version"); break;
		case StreamErrorXmlNotWellFormed: Log("gloox", "Stream error: XML Not well formed"); break;
		case StreamErrorUndefined: Log("gloox", "Stream error: Error undefined"); break;
	};

	switch (j->authError()) {
		case AuthErrorUndefined: Log("gloox", "Auth error: Error undefined"); break;
		case SaslAborted: Log("gloox", "Auth error: Sasl aborted"); break;
		case SaslIncorrectEncoding: Log("gloox", "Auth error: Sasl incorrect encoding"); break;        
		case SaslInvalidAuthzid: Log("gloox", "Auth error: Sasl invalid authzid"); break;
		case SaslInvalidMechanism: Log("gloox", "Auth error: Sasl invalid mechanism"); break;
		case SaslMalformedRequest: Log("gloox", "Auth error: Sasl malformed request"); break;
		case SaslMechanismTooWeak: Log("gloox", "Auth error: Sasl mechanism too weak"); break;
		case SaslNotAuthorized: Log("gloox", "Auth error: Sasl Not authorized"); break;
		case SaslTemporaryAuthFailure: Log("gloox", "Auth error: Sasl temporary auth failure"); break;
		case NonSaslConflict: Log("gloox", "Auth error: Non sasl conflict"); break;
		case NonSaslNotAcceptable: Log("gloox", "Auth error: Non sasl not acceptable"); break;
		case NonSaslNotAuthorized: Log("gloox", "Auth error: Non sasl not authorized"); break;
	};

	Log("gloox", "trying to reconnect after 3 seconds");
	g_timeout_add_seconds(3, &transportReconnect, NULL);

	if (connectIO) {
		g_source_remove(connectID);
		connectIO = NULL;
	}
}

void BalancerComponent::transportConnect() {
	m_reconnectCount++;
	j->connect(false);
	int mysock = dynamic_cast<ConnectionTCPClient*>( j->connectionImpl() )->socket();
	if (mysock > 0) {
		connectIO = g_io_channel_unix_new(mysock);
		connectID = g_io_add_watch(connectIO, (GIOCondition) READ_COND, &transportDataReceived, NULL);
	}
}

bool BalancerComponent::onTLSConnect(const CertInfo & info) {
	return false;
}

BalancerComponent* BalancerComponent::m_pInstance = NULL;

static void spectrum_sigint_handler(int sig) {
	delete BalancerComponent::instance();
}

static void spectrum_sigterm_handler(int sig) {
	delete BalancerComponent::instance();
}

#ifndef WIN32
static void spectrum_sigchld_handler(int sig)
{
	int status;
	pid_t pid;

	do {
		pid = waitpid(-1, &status, WNOHANG);
	} while (pid != 0 && pid != (pid_t)-1);

	if ((pid == (pid_t) - 1) && (errno != ECHILD)) {
		char errmsg[BUFSIZ];
		snprintf(errmsg, BUFSIZ, "Warning: waitpid() returned %d", pid);
		perror(errmsg);
	}
}
static void spectrum_sighup_handler(int sig) {
	BalancerComponent::instance()->loadConfigFile();
}
#endif

int main( int argc, char* argv[] ) {
	GError *error = NULL;
	GOptionContext *context;
	context = g_option_context_new("config_file_name or profile name");
	g_option_context_add_main_entries(context, options_entries, "");
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		std::cout << "option parsing failed: " << error->message << "\n";
		return -1;
	}

	if (ver) {
		std::cout << VERSION << "\n";
		g_option_context_free(context);
		return 0;
	}

	if (argc != 2) {
#ifdef WIN32
		std::cout << "Usage: spectrum.exe <configuration_file.cfg>\n";
#else

#if GLIB_CHECK_VERSION(2,14,0)
	std::cout << g_option_context_get_help(context, FALSE, NULL);
#else
	std::cout << "Usage: spectrum <configuration_file.cfg>\n";
	std::cout << "See \"man spectrum\" for more info.\n";
#endif
		
#endif
	}
	else {
#ifndef WIN32
		signal(SIGPIPE, SIG_IGN);

		if (signal(SIGCHLD, spectrum_sigchld_handler) == SIG_ERR) {
			std::cout << "SIGCHLD handler can't be set\n";
			g_option_context_free(context);
			return -1;
		}

		if (signal(SIGINT, spectrum_sigint_handler) == SIG_ERR) {
			std::cout << "SIGINT handler can't be set\n";
			g_option_context_free(context);
			return -1;
		}

		if (signal(SIGTERM, spectrum_sigterm_handler) == SIG_ERR) {
			std::cout << "SIGTERM handler can't be set\n";
			g_option_context_free(context);
			return -1;
		}

		struct sigaction sa;
		memset(&sa, 0, sizeof(sa)); 
		sa.sa_handler = spectrum_sighup_handler;
		if (sigaction(SIGHUP, &sa, NULL)) {
			std::cout << "SIGHUP handler can't be set\n";
			g_option_context_free(context);
			return -1;
		}
#endif
		std::string config(argv[1]);
		new BalancerComponent(config);
	}
	g_option_context_free(context);
}

