// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "PcapEthernetTransport.h"

#include "pcap.h"

class LibPcapEthernetTransport final : public PcapEthernetTransport
{
public:
	LibPcapEthernetTransport() = default;
	~LibPcapEthernetTransport() override;

	LibPcapEthernetTransport(const LibPcapEthernetTransport&) = delete;
	LibPcapEthernetTransport& operator=(const LibPcapEthernetTransport&) = delete;

	bool OpenLive(const std::string& adapter, bool promiscuous) override;
	bool ValidateEthernetDatalink() override;
	bool CompileAndSetSwitchedFilter(const PacketReader::MAC_Address& mac) override;
	bool ReceiveOne(NetPacket* pkt) override;
	bool Send(const NetPacket* pkt) override;

	bool IsReady() const override;
	bool Blocking() const override;
	void Shutdown() override;

private:
	pcap_t* m_handle = nullptr;
	bool m_blocking = false;
};
