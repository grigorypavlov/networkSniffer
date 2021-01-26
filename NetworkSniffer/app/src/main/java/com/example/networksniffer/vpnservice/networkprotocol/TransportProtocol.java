package com.example.networksniffer.vpnservice.networkprotocol;

public enum TransportProtocol {
    TCP(6),
    UDP(17),
    Other(0xFF);

    private int protocolNumber;

    /** Constructor */
    TransportProtocol(int protocolNumber) {
        this.protocolNumber = protocolNumber;
    }

    /** Create an enum from a number
     * @param protocolNumber Number to turn into enum
     * @return Returns the enum
     * */
    public static TransportProtocol NumberToEnum(int protocolNumber) {
        if (protocolNumber == 6)
            return TCP;
        else if (protocolNumber == 17)
            return UDP;
        else
            return Other;
    }

    /** @return Returns the protocol number */
    public int GetNumber() {
        return protocolNumber;
    }
}
