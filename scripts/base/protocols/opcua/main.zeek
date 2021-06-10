##! Base Opcua analysis script

module Opcua;

@load ./consts

export{
    redef enum Log::ID += { LOG };

    global log_policy: Log::PolicyHook;

    type Info: record {
        ts:        time         &log;
        uid:       string       &log;
        id:        conn_id      &log;
        message_type: string    &log &optional;
        message_size: count     &log &optional;
    };

    global log_opcua: event(rec: Info);
}

redef record connection += {
    opcua: Info &optional;
};


event zeek_init() &priority=5
    {
    Log::create_stream(Opcua::LOG, [$columns=Info, $ev=log_opcua, $path="opcua", $policy=log_policy]);
    }

event opcua_event(c: connection, is_orig: bool, message_type: count, message_size: count) &priority=5
    {
    c$opcua = [$ts=network_time(), $uid=c$uid, $id=c$id];
    c$opcua$message_type = messages_types[message_type];
    c$opcua$message_size = message_size;
    Log::write(LOG, c$opcua);
    }