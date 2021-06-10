#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include <unordered_map>
#include <string>


namespace zeek::analyzer::opcua{

class Opcua_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer{
public:
    // explicit used to avoid implicit cast type Connection
    // to type Opcua_Analyzer - compiler will say about
    // problem  
    explicit Opcua_Analyzer(Connection* conn);

    void DeliverStream(int len, const u_char* data, bool orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn)
        {
        fprintf(stdout, "Inside Instantiate facotry method before calling new Opcua_Analyzer");
        return new Opcua_Analyzer(conn);
        }
protected:
    static const std::unordered_map<std::string, uint8_t> opcua_messages;
};
}