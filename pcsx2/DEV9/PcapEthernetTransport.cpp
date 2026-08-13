// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PcapEthernetTransport.h"

#include "LibPcapEthernetTransport.h"

std::unique_ptr<PcapEthernetTransport> PcapEthernetTransport::CreateDefault()
{
	return std::make_unique<LibPcapEthernetTransport>();
}
