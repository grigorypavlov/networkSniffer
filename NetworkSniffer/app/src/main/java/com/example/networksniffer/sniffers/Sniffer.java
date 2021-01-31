package com.example.networksniffer.sniffers;

import com.example.networksniffer.observerpattern.IPublisher;
import com.example.networksniffer.observerpattern.ISubscriber;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;

/** Sniffer
 * This is a singleton class!
 */
public class Sniffer implements IPublisher {
    private static Sniffer sniffer = new Sniffer(); // Instance of itself
    private Packet currPacket;

    /** Private constructor
     * prevents any other class from instantiating
     */
    private Sniffer() { }

    /** Get the singleton instance
     * @return returns the instance
     */
    public static Sniffer getInstance() {
        return sniffer;
    }

    /** Add a new Packet
     * Notifies all subscribers of the new packet
     */
    public void UpdatePacket(Packet packet) {
        this.currPacket = packet;
        Notify();
    }

    /** Get the current packet
     * @return Returns the current packet
     */
    public Packet GetPacket() {
        return currPacket;
    }

    /** Notifies all subscriber of the current packet */
    public void Notify() {
        for (ISubscriber sub: subscribers) {
            sub.Update(currPacket);
        }
    }
}
