##! Base Opcua analysis script

module Opcua;

@load ./consts

export{
    redef enum Log::ID += { LOG };

    global log_policy: Log::PolicyHook;

    type Info: record {
        ts:        time         &log;
        uid:       string       &log;
        orig:      bool         &log;
        message_type: string    &log &optional;
        message_size: count     &log &optional;
    };

    global log_opcua: event(rec: Info);
}

redef record connection += {
    opcua: Info &optional;
};

const ports = { 12001/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
    {
    Log::create_stream(Opcua::LOG, [$columns=Info, $ev=log_opcua, $path="opcua", $policy=log_policy]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_OPCUA, ports);
    }

event opcua_event(c: connection, is_orig: bool, message_type: count, message_size: count) &priority=5
    {
    c$opcua = [$ts=network_time(), $uid=c$uid, $orig=is_orig];
    c$opcua$message_type = messages_types[message_type];
    c$opcua$message_size = message_size;
    Log::write(LOG, c$opcua);
    }