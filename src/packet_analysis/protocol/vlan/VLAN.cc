// See the file "COPYING" in the main distribution directory for copyright.

#include "VLAN.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::VLAN;

VLANAnalyzer::VLANAnalyzer()
	: zeek::packet_analysis::Analyzer("VLAN")
	{
	}

bool VLANAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	int hdr_size = 4;

	if ( hdr_size >= len )
		{
		packet->Weird("truncated_VLAN_header");
		return false;
		}

	auto& vlan_ref = packet->vlan != 0 ? packet->inner_vlan : packet->vlan;
	vlan_ref = ((data[0] << 8u) + data[1]) & 0xfff;

	uint32_t protocol = ((data[2] << 8u) + data[3]);
	packet->eth_type = protocol;
	packet->hdr_size += hdr_size;

	// Skip the VLAN header
	return ForwardPacket(len - hdr_size, data + hdr_size, packet, protocol);
	}
