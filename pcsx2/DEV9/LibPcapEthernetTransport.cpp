// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "LibPcapEthernetTransport.h"

#include "common/Assertions.h"
#include "common/Console.h"
#include "net.h"

#include <cstdio>
#include <cstring>

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

LibPcapEthernetTransport::~LibPcapEthernetTransport()
{
	Shutdown();
}

void LibPcapEthernetTransport::Shutdown()
{
	if (m_handle)
	{
		pcap_close(m_handle);
		m_handle = nullptr;
	}
}

bool LibPcapEthernetTransport::IsReady() const
{
	return m_handle != nullptr;
}

bool LibPcapEthernetTransport::Blocking() const
{
	return m_blocking;
}

bool LibPcapEthernetTransport::OpenLive(const std::string& adapter, bool promiscuous)
{
	Shutdown();

	char errbuf[PCAP_ERRBUF_SIZE];
	Console.WriteLn("DEV9: Opening adapter '%s'...", adapter.c_str());

	if ((m_handle = pcap_open_live(adapter.c_str(),
			 65536,
			 promiscuous ? 1 : 0,
			 1,
			 errbuf)) == nullptr)
	{
		Console.Error("DEV9: %s", errbuf);
#if defined(__linux__)
		Console.Error("DEV9: PCAP on Linux requires CAP_NET_RAW and CAP_NET_ADMIN capabilities.");
		Console.Error("DEV9: Flatpak: raw packet capture is not supported; use the Sockets backend instead.");
		Console.Error("DEV9: AppImage: extract the image first (--appimage-extract), then run setcap on the extracted binary.");
		Console.Error("DEV9: Note: applying file capabilities to the main PCSX2 executable breaks Steam overlay/Input.");
#endif
		Console.Error("DEV9: Unable to open the adapter. %s is not supported by pcap", adapter.c_str());
		return false;
	}

	if (pcap_setnonblock(m_handle, 1, errbuf) == -1)
	{
		Console.Error("DEV9: Error setting non-blocking: %s", pcap_geterr(m_handle));
		Console.Error("DEV9: Continuing in blocking mode");
		m_blocking = true;
	}
	else
	{
		m_blocking = false;
	}

	return true;
}

bool LibPcapEthernetTransport::ValidateEthernetDatalink()
{
	pxAssert(m_handle);

	const int dlt = pcap_datalink(m_handle);
	const char* dlt_name = pcap_datalink_val_to_name(dlt);

	Console.WriteLn("DEV9: Device uses DLT %d: %s", dlt, dlt_name);
	switch (dlt)
	{
		case DLT_EN10MB:
			break;
		default:
			Console.Error("ERROR: Unsupported DataLink Type (%d): %s", dlt, dlt_name);
			Shutdown();
			return false;
	}

	Console.WriteLn("DEV9: Adapter Ok.");
	return true;
}

bool LibPcapEthernetTransport::CompileAndSetSwitchedFilter(const PacketReader::MAC_Address& mac)
{
	pxAssert(m_handle);

	bpf_program fp;

	char filter[128];
	std::snprintf(filter, std::size(filter), "ether broadcast or ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		mac.bytes[0], mac.bytes[1], mac.bytes[2], mac.bytes[3], mac.bytes[4], mac.bytes[5]);

	if (pcap_compile(m_handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		Console.Error("DEV9: Error calling pcap_compile: %s", pcap_geterr(m_handle));
		return false;
	}

	int setFilterRet;
	if ((setFilterRet = pcap_setfilter(m_handle, &fp)) == -1)
		Console.Error("DEV9: Error setting filter: %s", pcap_geterr(m_handle));

	pcap_freecode(&fp);
	return setFilterRet != -1;
}

bool LibPcapEthernetTransport::ReceiveOne(NetPacket* pkt)
{
	pxAssert(m_handle);

	pcap_pkthdr* header;
	const u_char* pkt_data;

	while (pcap_next_ex(m_handle, &header, &pkt_data) > 0)
	{
		if (header->len > 1518)
		{
			Console.Error("DEV9: Dropped jumbo frame of size: %u", header->len);
			continue;
		}

		pxAssert(header->len == header->caplen);

		memcpy(pkt->buffer, pkt_data, header->len);
		pkt->size = static_cast<int>(header->len);
		return true;
	}

	return false;
}

bool LibPcapEthernetTransport::Send(const NetPacket* pkt)
{
	pxAssert(m_handle);
	return pcap_sendpacket(m_handle, reinterpret_cast<const u_char*>(pkt->buffer), pkt->size) == 0;
}
