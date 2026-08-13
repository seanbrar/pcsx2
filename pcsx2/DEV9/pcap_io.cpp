// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "common/Assertions.h"
#include <algorithm>
#include <memory>

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include "common/StringUtil.h"
#include <WinSock2.h>
#include <iphlpapi.h>
#endif

#include <stdio.h>
#include "pcap.h"
#include "pcap_io.h"
#include "DEV9.h"
#include "AdapterUtils.h"
#include "net.h"
#include "PacketReader/EthernetFrame.h"
#include "PacketReader/EthernetFrameEditor.h"
#include "PacketReader/ARP/ARP_PacketEditor.h"

#ifdef _WIN32
#define PCAPPREFIX "\\Device\\NPF_"
#endif

using namespace PacketReader;
using namespace PacketReader::ARP;
using namespace PacketReader::IP;

PCAPAdapter::PCAPAdapter()
	: NetAdapter()
{
	if (!EmuConfig.DEV9.EthEnable)
		return;
#ifdef _WIN32
	if (!load_pcap())
		return;
#endif

#ifdef _WIN32
	std::string pcapAdapter = PCAPPREFIX + EmuConfig.DEV9.EthDevice;
#else
	std::string pcapAdapter = EmuConfig.DEV9.EthDevice;
#endif

	switched = EmuConfig.DEV9.EthApi == Pcsx2Config::DEV9Options::NetApi::PCAP_Switched;

	m_transport = PcapEthernetTransport::CreateDefault();
	if (!m_transport->OpenLive(pcapAdapter, switched))
	{
		Console.Error("DEV9: Can't open Device '%s'", EmuConfig.DEV9.EthDevice.c_str());
		m_transport.reset();
		return;
	}

	if (!m_transport->ValidateEthernetDatalink())
	{
		Console.Error("DEV9: Can't open Device '%s'", EmuConfig.DEV9.EthDevice.c_str());
		m_transport.reset();
		return;
	}

	AdapterUtils::Adapter adapter;
	AdapterUtils::AdapterBuffer buffer;
	std::optional<MAC_Address> adMAC = std::nullopt;
	const bool foundAdapter = AdapterUtils::GetAdapter(EmuConfig.DEV9.EthDevice, &adapter, &buffer);
	if (foundAdapter)
		adMAC = AdapterUtils::GetAdapterMAC(&adapter);
	else
		Console.Error("DEV9: Failed to get adapter information");

	if (adMAC.has_value())
	{
		hostMAC = adMAC.value();
		MAC_Address newMAC = ps2MAC;

		//Lets take the hosts last 2 bytes to make it unique on Xlink
		newMAC.bytes[5] = hostMAC.bytes[4];
		newMAC.bytes[4] = hostMAC.bytes[5];

		SetMACAddress(&newMAC);
	}
	else
	{
		Console.Error("DEV9: Failed to get MAC address for adapter");
		m_transport.reset();
		return;
	}

	if (switched && !m_transport->CompileAndSetSwitchedFilter(ps2MAC))
	{
		m_transport.reset();
		Console.Error("DEV9: Can't open Device '%s'", EmuConfig.DEV9.EthDevice.c_str());
		return;
	}

	if (foundAdapter)
		InitInternalServer(&adapter);
	else
		InitInternalServer(nullptr);
}
AdapterOptions PCAPAdapter::GetAdapterOptions()
{
	return AdapterOptions::None;
}
bool PCAPAdapter::blocks()
{
	pxAssert(m_transport && m_transport->IsReady());
	return m_transport->Blocking();
}
bool PCAPAdapter::isInitialised()
{
	return m_transport && m_transport->IsReady();
}
//gets a packet.rv :true success
bool PCAPAdapter::recv(NetPacket* pkt)
{
	pxAssert(m_transport && m_transport->IsReady());

	if (!m_transport->Blocking() && NetAdapter::recv(pkt))
		return true;

	while (m_transport->ReceiveOne(pkt))
	{
		if (!switched)
			SetMACBridgedRecv(pkt);

		if (VerifyPkt(pkt, pkt->size))
		{
			HandleFrameCheckSequence(pkt);

			// FCS (if present) has been removed, apply correct limit
			if (pkt->size > 1514)
			{
				Console.Error("DEV9: Dropped jumbo frame of size: %u", pkt->size);
				continue;
			}

			InspectRecv(pkt);
			return true;
		}
		// continue.
	}

	return false;
}
//sends the packet .rv :true success
bool PCAPAdapter::send(NetPacket* pkt)
{
	pxAssert(m_transport && m_transport->IsReady());

	InspectSend(pkt);
	if (NetAdapter::send(pkt))
		return true;

	// TODO: loopback broadcast packets to host pc in switched mode.
	if (!switched)
		SetMACBridgedSend(pkt);

	return m_transport->Send(pkt);
}

void PCAPAdapter::reloadSettings()
{
	AdapterUtils::Adapter adapter;
	AdapterUtils::AdapterBuffer buffer;
	if (AdapterUtils::GetAdapter(EmuConfig.DEV9.EthDevice, &adapter, &buffer))
		ReloadInternalServer(&adapter);
	else
		ReloadInternalServer(nullptr);
}

PCAPAdapter::~PCAPAdapter() = default;

std::vector<AdapterEntry> PCAPAdapter::GetAdapters()
{
	std::vector<AdapterEntry> nic;

#ifdef _WIN32
	if (!load_pcap())
		return nic;
#endif

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevs;
	pcap_if_t* d;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
		return nic;

	d = alldevs;
	while (d != NULL)
	{
		AdapterEntry entry;
		entry.type = Pcsx2Config::DEV9Options::NetApi::PCAP_Switched;
#ifdef _WIN32
		//guid
		if (!std::string_view(d->name).starts_with(PCAPPREFIX))
		{
			Console.Error("PCAP: Unexpected Device: ", d->name);
			d = d->next;
			continue;
		}

		entry.guid = std::string(&d->name[strlen(PCAPPREFIX)]);

		IP_ADAPTER_ADDRESSES adapterInfo;
		AdapterUtils::AdapterBuffer buffer;

		if (AdapterUtils::GetAdapter(entry.guid, &adapterInfo, &buffer))
			entry.name = StringUtil::WideStringToUTF8String(std::wstring(adapterInfo.FriendlyName));
		else
		{
			//have to use description
			//NPCAP 1.10 is using a version of pcap that doesn't
			//allow us to set it to use UTF8
			//see https://github.com/nmap/npcap/issues/276
			//We have to convert from ANSI to wstring, to then convert to UTF8
			const int len_desc = strlen(d->description) + 1;
			const int len_buf = MultiByteToWideChar(CP_ACP, 0, d->description, len_desc, nullptr, 0);

			std::unique_ptr<wchar_t[]> buf = std::make_unique<wchar_t[]>(len_buf);
			MultiByteToWideChar(CP_ACP, 0, d->description, len_desc, buf.get(), len_buf);

			entry.name = StringUtil::WideStringToUTF8String(std::wstring(buf.get()));
		}
#else
		entry.name = std::string(d->name);
		entry.guid = std::string(d->name);
#endif

		nic.push_back(entry);
		entry.type = Pcsx2Config::DEV9Options::NetApi::PCAP_Bridged;
		nic.push_back(entry);
		d = d->next;
	}

	return nic;
}

void PCAPAdapter::SetMACBridgedRecv(NetPacket* pkt)
{
	EthernetFrameEditor frame(pkt);
	if (frame.GetProtocol() == static_cast<u16>(EtherType::IPv4)) // IP
	{
		// Compare DEST IP in IP with the PS2's IP, if they match, change DEST MAC to ps2MAC.
		PayloadPtrEditor* payload = frame.GetPayload();
		IP_Packet ippkt(payload->data, payload->GetLength());
		if (ippkt.destinationIP == ps2IP)
			frame.SetDestinationMAC(ps2MAC);
	}
	if (frame.GetProtocol() == static_cast<u16>(EtherType::ARP)) // ARP
	{
		// Compare DEST IP in ARP with the PS2's IP, if they match, DEST MAC to ps2MAC on both ARP and ETH Packet headers.
		ARP_PacketEditor arpPkt(frame.GetPayload());
		if (*(IP_Address*)arpPkt.TargetProtocolAddress() == ps2IP)
		{
			frame.SetDestinationMAC(ps2MAC);
			*(MAC_Address*)arpPkt.TargetHardwareAddress() = ps2MAC;
		}
	}
}

void PCAPAdapter::SetMACBridgedSend(NetPacket* pkt)
{
	EthernetFrameEditor frame(pkt);
	if (frame.GetProtocol() == static_cast<u16>(EtherType::IPv4)) // IP
	{
		PayloadPtrEditor* payload = frame.GetPayload();
		IP_Packet ippkt(payload->data, payload->GetLength());
		ps2IP = ippkt.sourceIP;
	}
	if (frame.GetProtocol() == static_cast<u16>(EtherType::ARP)) // ARP
	{
		ARP_PacketEditor arpPkt(frame.GetPayload());
		ps2IP = *(IP_Address*)arpPkt.SenderProtocolAddress();
		*(MAC_Address*)arpPkt.SenderHardwareAddress() = hostMAC;
	}
	frame.SetSourceMAC(hostMAC);
}

/*
 * Strips the Frame Check Sequence if we manage to capture it.
 * 
 * On Windows, (some?) Intel NICs can be configured to capture FCS.
 * 
 * Linux can be configure to capture FCS, using `ethtool -K <interface> rx-fcs on` on supported devices.
 * Support for capturing FCS can be checked with `ethtool -k <interface> | grep rx-fcs`.
 * if it's `off [Fixed]`, then the interface/driver dosn't support capturing FCS.
 * 
 * BSD based systems might capture FCS by default.
 * 
 * Packets sent by host won't have FCS, We identify these packets by checking the source MAC address.
 * Packets sent by another application via packet injection also won't have FCS and may not match the adapter MAC.
 */
void PCAPAdapter::HandleFrameCheckSequence(NetPacket* pkt)
{
	EthernetFrameEditor frame(pkt);
	if (frame.GetSourceMAC() == hostMAC)
		return;

	// There is a (very) low chance of the last 4 bytes of payload somehow acting as a valid checksum for the whole Ethernet frame.
	// For EtherTypes we already can parse, trim the Ethernet frame based on the payload length.

	int payloadSize = -1;
	if (frame.GetProtocol() == static_cast<u16>(EtherType::IPv4)) // IP
	{
		PayloadPtrEditor* payload = frame.GetPayload();
		IP_Packet ippkt(payload->data, payload->GetLength());
		payloadSize = ippkt.GetLength();
	}
	if (frame.GetProtocol() == static_cast<u16>(EtherType::ARP)) // ARP
	{
		ARP_PacketEditor arpPkt(frame.GetPayload());
		payloadSize = arpPkt.GetLength();
	}

	if (payloadSize != -1)
	{
		// Minumum frame size is 60 + 4 byte FCS.
		// Virtual NICs may omit this padding, so check we arn't increasing pkt size.
		payloadSize = std::min(std::max(payloadSize, 60 - frame.headerLength), pkt->size);

		pkt->size = payloadSize + frame.headerLength;
		return;
	}

	// Ethertype unknown, rely on checking for a FCS.
	if (ValidateEtherFrame(pkt))
		pkt->size -= 4;
}

bool PCAPAdapter::ValidateEtherFrame(NetPacket* pkt)
{
	u32 crc = 0xFFFFFFFF;

	for (int i = 0; i < pkt->size; i++)
	{
		// Neads unsigned value
		crc = crc ^ static_cast<u8>(pkt->buffer[i]);
		for (int bit = 0; bit < 8; bit++)
		{
			if ((crc & 1) != 0)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc = (crc >> 1);
		}
	}

	crc = ~crc;

	return crc == 0x2144DF1C;
}
