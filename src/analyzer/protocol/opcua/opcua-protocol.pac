


type Opcua_TransportHeader = record {
    message_type: number;
    chunk_type: uint8;
    message_size: uint32; 
} &byteorder = bigendian, &let {
    deliver: bool = $context.flow.deliver_opcua_event(this);
}