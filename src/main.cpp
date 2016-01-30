/*
 * Copyright (C) 2012 Incognito
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "main.h"

#include <boost/thread.hpp>

#include <sdk/plugin.h>

#include <queue>
#include <set>
#include <string>
#include <vector>

#ifdef _WIN32
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
	#include <netdb.h>
#endif

std::set<AMX*> interfaces;
std::queue<Message> messages;

boost::mutex mutex;

logprintf_t logprintf;

void dns(const std::string &input, int extra)
{
	char buffer[MAX_IP];
	std::string output = input;
	struct addrinfo *result = NULL;
	if (!getaddrinfo(input.c_str(), NULL, NULL, &result))
	{
		if (!getnameinfo(result->ai_addr, result->ai_addrlen, buffer, MAX_IP, NULL, 0, NI_NUMERICHOST))
		{
			output = buffer;
		}
		freeaddrinfo(result);
	}
	Message message;
	message.array.push_back(OnDNS);
	message.array.push_back(extra);
	message.buffer.push_back(output);
	message.buffer.push_back(input);
	boost::mutex::scoped_lock lock(mutex);
	messages.push(message);
}

void rdns(const std::string &input, int extra)
{
	char buffer[MAX_HOST];
	std::string output = input;
	struct sockaddr_in address;
	address.sin_addr.s_addr = inet_addr(input.c_str());
	address.sin_family = AF_INET;
	if (!getnameinfo(reinterpret_cast<struct sockaddr*>(&address), sizeof(struct sockaddr), buffer, MAX_HOST, NULL, 0, NI_NUMERICSERV))
	{
		output = buffer;
	}
	Message message;
	message.array.push_back(OnReverseDNS);
	message.array.push_back(extra);
	message.buffer.push_back(output);
	message.buffer.push_back(input);
	boost::mutex::scoped_lock lock(mutex);
	messages.push(message);
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES | SUPPORTS_PROCESS_TICK;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t)ppData[PLUGIN_DATA_LOGPRINTF];
	logprintf("\n\n*** DNS Plugin v%s by Incognito loaded ***\n", PLUGIN_VERSION);
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	logprintf("\n\n*** DNS Plugin v%s by Incognito unloaded ***\n", PLUGIN_VERSION);    
}

static cell AMX_NATIVE_CALL n_dns(AMX *amx, cell *params)
{
	CHECK_PARAMS(2, "dns");
	char *buffer = NULL;
	amx_StrParam(amx, params[1], buffer);
	if (buffer == NULL)
	{
		logprintf("*** dns: Expecting input string");
		return 0;
	}
	if (static_cast<int>(inet_addr(buffer)) != -1)
	{
		logprintf("*** dns: Expecting hostname, but found IP address (%s)", buffer);
		return 0;
	}
	std::string input = buffer;
	boost::thread thread(dns, input, static_cast<int>(params[2]));
	return 1;
}

static cell AMX_NATIVE_CALL n_rdns(AMX *amx, cell *params)
{
	CHECK_PARAMS(2, "rdns");
	char *buffer = NULL;
	amx_StrParam(amx, params[1], buffer);
	if (buffer == NULL)
	{
		logprintf("*** rdns: Expecting input string");
		return 0;
	}
	if (static_cast<int>(inet_addr(buffer)) == -1)
	{
		logprintf("*** rdns: Invalid IP address (%s) entered", buffer);
		return 0;
	}
	std::string input = buffer;
	boost::thread thread(rdns, input, static_cast<int>(params[2]));
	return 1;
}

AMX_NATIVE_INFO natives[] =
{
	{ "dns", n_dns },
	{ "rdns", n_rdns },
	{ 0, 0 }
};

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx)
{
	interfaces.insert(amx);
	return amx_Register(amx, natives, -1);
}

PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx)
{
	interfaces.erase(amx);
	return AMX_ERR_NONE;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	if (!messages.empty())
	{
		boost::mutex::scoped_lock lock(mutex);
		Message message(messages.front());
		messages.pop();
		lock.unlock();
		for (std::set<AMX*>::iterator a = interfaces.begin(); a != interfaces.end(); a++)
		{
			cell amxAddresses[2] = { 0 };
			int amxIndex = 0;
			switch (message.array.at(0))
			{
				case OnDNS:
				{
					if (!amx_FindPublic(*a, "OnDNS", &amxIndex))
					{
						amx_Push(*a, message.array.at(1));
						amx_PushString(*a, &amxAddresses[0], NULL, message.buffer.at(0).c_str(), 0, 0);
						amx_PushString(*a, &amxAddresses[1], NULL, message.buffer.at(1).c_str(), 0, 0);
						amx_Exec(*a, NULL, amxIndex);
						amx_Release(*a, amxAddresses[0]);
						amx_Release(*a, amxAddresses[1]);
					}
					break;
				}
				case OnReverseDNS:
				{
					if (!amx_FindPublic(*a, "OnReverseDNS", &amxIndex))
					{
						amx_Push(*a, message.array.at(1));
						amx_PushString(*a, &amxAddresses[0], NULL, message.buffer.at(0).c_str(), 0, 0);
						amx_PushString(*a, &amxAddresses[1], NULL, message.buffer.at(1).c_str(), 0, 0);
						amx_Exec(*a, NULL, amxIndex);
						amx_Release(*a, amxAddresses[0]);
						amx_Release(*a, amxAddresses[1]);
					}
					break;
				}
			}
		}
	}
}
