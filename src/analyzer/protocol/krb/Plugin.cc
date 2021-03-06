//See the file in the main distribution directory for copyright.

#include "KRB.h"
#include "KRB_TCP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace zeek::plugin::detail::Zeek_KRB {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("KRB", zeek::analyzer::krb::KRB_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("KRB_TCP", zeek::analyzer::krb_tcp::KRB_Analyzer::Instantiate));
		zeek::plugin::Configuration config;
		config.name = "Zeek::KRB";
		config.description = "Kerberos analyzer";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_KRB
