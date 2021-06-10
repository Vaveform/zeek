#include "zeek/zeek-config.h"
#include "zeek/analyzer/protocol/opcua/Opcua.h"
#include <stdlib.h>
#include "zeek/ZeekString.h"
#include "zeek/NetVar.h"
#include "zeek/Event.h"
#include "zeek/Base64.h"
#include "zeek/RuleMatcher.h"
#include "zeek/analyzer/Manager.h"

#include "zeek/analyzer/protocol/opcua/events.bif.h"


namespace zeek::analyzer::opcua {
    
Opcua_Analyzer::Opcua_Analyzer(Connection* conn) 
: analyzer::tcp::TCP_ApplicationAnalyzer("Opcua", conn)
    {
    fprintf(stdout, "Created Opcua_Analyzer derived from TCP analyzer");
    }


const std::unordered_map<std::string, uint8_t> Opcua_Analyzer::opcua_messages{
    {"HEL", 0u},
    {"ACK", 1u},
    {"ERR", 2u},
    {"RHE", 3u},
    {"MSG", 4u},
    {"OPN", 5u},
    {"CLO", 6u}
};

void Opcua_Analyzer::DeliverStream(int length, const u_char* data, bool orig)
    {
    fprintf(stdout, "Input to Opcua_Analyzer::DeliverStream with length of stream: %d\n", length);
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, orig);


    const char* line = reinterpret_cast<const char*>(data);
    const char* end_of_line = line + length;
    size_t current_position = 0;
    for(int i = 0; i < length; i++){
        fprintf(stdout, "byte number %d: %c\n", i, line[i]);
    }

    // Check if header is full
    if(length < 8)
        return;


    // Parsing message type
    char message_type[3];
    memcpy(message_type, line, 3);
    current_position += 3;

    fprintf(stdout, "Parsed message_type: %c%c%c\n", message_type[0], message_type[1], message_type[2]);

    if(this->opcua_messages.find(message_type) == this->opcua_messages.end())
        return;
    // getting message type from hash table of types
    uint8_t message_code = this->opcua_messages.at(message_type);
    ProtocolConfirmation();

    // Parsing chunk type
    char chunk_type = line[3];
    ++current_position;

    fprintf(stdout, "Parsed chunk type: %c\n", chunk_type);

    // Parsing message size
    uint32_t message_size = 0;
    uint32_t buffer_value = 0;
    for(int i = 0; current_position < 8; current_position++, i++){
        buffer_value = line[current_position];
        buffer_value = buffer_value << (8 * i);
        message_size = message_size | buffer_value;
    }

    fprintf(stdout, "Parsed message size: %u\n", message_size);


    // Args for event from events.bif
    Args vl = {
        ConnVal(), 
        val_mgr->Bool(orig),
        val_mgr->Count(message_code),
        val_mgr->Count(message_size)
    };

    // Pointer to event from events.bif
    EventHandlerPtr f = opcua_event;

    EnqueueConnEvent(f, std::move(vl));

	ForwardStream(length, data, orig);
    }
}