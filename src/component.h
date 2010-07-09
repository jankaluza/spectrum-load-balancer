/**
 * XMPP - libpurple transport
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

#ifndef _S_COMPONENT_H
#define _S_COMPONENT_H

#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sstream>

#include <glib.h>

#include <gloox/component.h>
#include <gloox/messagehandler.h>
#include <gloox/connectiontcpclient.h>
#include <gloox/disco.h>
#include <gloox/connectionlistener.h>
#include <gloox/presencehandler.h>
#include <gloox/subscriptionhandler.h>
#include <gloox/socks5bytestreamserver.h>
#include <gloox/siprofileft.h>
#include <gloox/message.h>
#include <gloox/eventhandler.h>
#include <gloox/vcardhandler.h>
#include <gloox/vcardmanager.h>

#include "configfile.h"
#include "log.h"
#include "transport_config.h"

#define READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

using namespace gloox;

extern LogClass Log_;

class BalancerComponent : ConnectionListener, LogHandler {
public:
	BalancerComponent(const std::string &config);
	~BalancerComponent();

	/*
	 * Returns pointer to GlooxMessageHandler class.
	 */
	static BalancerComponent *instance() { return m_pInstance; }

	void transportConnect();


	/*
	 * Gloox callbacks
	 */
	void onConnect();
	void onDisconnect(ConnectionError e);
	void onSessionCreateError(const Error *error);
	bool onTLSConnect(const CertInfo & info);

	void handleLog(LogLevel level, LogArea area, const std::string &message);

	bool loadConfigFile(const std::string &config = "");
	Component *j;


private:
	Configuration m_configuration;				// configuration struct
	GIOChannel *connectIO;						// GIOChannel for Gloox socket
	guint connectID;
	bool m_firstConnection;						// true if transporConnect is called for first time
	static BalancerComponent* m_pInstance;
	GMainLoop *m_loop;
	std::string m_config;
	unsigned int m_reconnectCount;
};

#endif
