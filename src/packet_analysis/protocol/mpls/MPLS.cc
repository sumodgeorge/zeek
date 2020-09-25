// See the file "COPYING" in the main distribution directory for copyright.

#include "MPLS.h"

using namespace zeek::packet_analysis::MPLS;

MPLSAnalyzer::MPLSAnalyzer()
	: zeek::packet_analysis::Analyzer("MPLS")
	{
	}

bool MPLSAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Skip the MPLS label stack.
	bool end_of_stack = false;
	int mpls_hdr_size = 4;

	while ( ! end_of_stack )
		{
		if ( mpls_hdr_size >= len )
			{
			packet->Weird("truncated_link_header");
			return false;
			}

		end_of_stack = *(data + 2u) & 0x01;
		data += mpls_hdr_size;
		len -= mpls_hdr_size;
		packet->hdr_size += mpls_hdr_size;
		}

	// According to RFC3032 the encapsulated protocol is not encoded.
	// We use the configured default analyzer.
	return ForwardPacket(len, data, packet);
	}
