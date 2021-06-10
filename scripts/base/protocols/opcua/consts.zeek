module Opcua;

export {
    const messages_types = {
        [0] = "HEL",
        [1] = "ACK",
        [2] = "ERR",
        [3] = "RHE",
        [4] = "MSG",
        [5] = "OPN",
        [6] = "CLO",
    } &default=function(i: count): string { return fmt("unknown%d", i); } &redef;
}