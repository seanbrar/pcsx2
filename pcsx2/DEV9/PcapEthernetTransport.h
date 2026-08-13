// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <memory>
#include <string>

#include "PacketReader/MAC_Address.h"

struct NetPacket;

class PcapEthernetTransport
{
public:
	virtual ~PcapEthernetTransport() = default;

	static std::unique_ptr<PcapEthernetTransport> CreateDefault();

	virtual bool OpenLive(const std::string& adapter, bool promiscuous) = 0;
	virtual bool ValidateEthernetDatalink() = 0;
	virtual bool CompileAndSetSwitchedFilter(const PacketReader::MAC_Address& mac) = 0;
	virtual bool ReceiveOne(NetPacket* pkt) = 0;
	virtual bool Send(const NetPacket* pkt) = 0;

	virtual bool IsReady() const = 0;
	virtual bool Blocking() const = 0;
	virtual void Shutdown() = 0;
};
