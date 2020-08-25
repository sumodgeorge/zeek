
%include binpac.pac
%include zeek.pac

%extern{
#include "events.bif.h"
%}

analyzer Syslog withcontext {
	connection:	Syslog_Conn;
	flow:		Syslog_Flow;
};

%include syslog-protocol.pac
%include syslog-analyzer.pac
