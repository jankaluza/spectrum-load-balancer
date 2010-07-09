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

#ifndef _SPECTRUM_CONFIG_FILE_H
#define _SPECTRUM_CONFIG_FILE_H

#include "glib.h"
#include <iostream>
#include <list>
#include <map>
#include <string>
#include "limits.h"
#include "log.h"

extern LogClass Log_;

// Structure used for storing transport configuration.
struct Configuration {
	std::string server;				// XMPP server address.
	std::string password;			// Password to connect server.
	std::string jid;				// Spectrum JID.
	std::string logfile;			// Log file.
	std::string pid_f;				// Pid file.
	int port;						// Server port.

	operator bool() const {
		return !server.empty();
	}
};

// Loads Spectrum config file, parses it and stores into Configuration structure.
class ConfigFile {
	public:
		// If filename is provided, loadFromFile is called automatically.
		ConfigFile(const std::string &filename = "");
		~ConfigFile();

		// Loads configuration from files.
		void loadFromFile(const std::string &file);

		// Loads configuration from data.
		void loadFromData(const std::string &data);

		// Returns parsed configuration.
		Configuration getConfiguration();

#ifndef TESTS
	private:
#endif
		GKeyFile *keyfile;
		bool m_loaded;
		std::string m_jid;
		std::string m_protocol;
		std::string m_appdata;
		std::string m_filename;
		std::string m_transport;
		int m_port;

		bool loadString(std::string &variable, const std::string &section, const std::string &key, const std::string &def = "required");
		bool loadInteger(int &variable, const std::string &section, const std::string &key, int def = INT_MAX);
		bool loadBoolean(bool &variable, const std::string &section, const std::string &key, bool def = false, bool required = false);
		bool loadStringList(std::list <std::string> &variable, const std::string &section, const std::string &key);
		bool loadHostPort(std::string &variable, int &port, const std::string &section, const std::string &key, const std::string &def_host = "required", const int &def_port = 0);
};

#endif
