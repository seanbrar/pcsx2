// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <memory>

#include "net.h"
#include "PcapEthernetTransport.h"
#include "PacketReader/MAC_Address.h"

#ifdef _WIN32
bool load_pcap();
void unload_pcap();
#endif

class PCAPAdapter : public NetAdapter
{
private:
	std::unique_ptr<PcapEthernetTransport> m_transport;

	bool switched;

	PacketReader::IP::IP_Address ps2IP{};
	PacketReader::MAC_Address hostMAC;

public:
	PCAPAdapter();
	virtual bool blocks();
	virtual bool isInitialised();
	//gets a packet.rv :true success
	virtual bool recv(NetPacket* pkt);
	//sends the packet and deletes it when done (if successful).rv :true success
	virtual bool send(NetPacket* pkt);
	virtual void reloadSettings();
	virtual ~PCAPAdapter();
	static std::vector<AdapterEntry> GetAdapters();
	static AdapterOptions GetAdapterOptions();

private:
	void SetMACBridgedRecv(NetPacket* pkt);
	void SetMACBridgedSend(NetPacket* pkt);

	void HandleFrameCheckSequence(NetPacket* pkt);
	bool ValidateEtherFrame(NetPacket* pkt);
};
