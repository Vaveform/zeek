#include "zeek/plugin/Plugin.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/opcua/Opcua.h"

namespace zeek::plugin::detail::Opc_UA{

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override
        {
        //fprintf(stdout, "Call registration component Opcua\n");
        zeek::plugin::Component *c = new zeek::analyzer::Component("Opcua", zeek::analyzer::opcua::Opcua_Analyzer::Instantiate);
        AddComponent(c);
        //fprintf(stdout, "Componet Opcua registration ended\n");
        zeek::plugin::Configuration config;
        config.name = "Zeek::Opcua";
        config.description = "Opcua analyzer";
        return config;
        }
} plugin;

}