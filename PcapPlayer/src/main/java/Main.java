import io.pkts.*;
import io.pkts.buffer.*;
import io.pkts.packet.*;
import io.pkts.protocol.*;

import java.io.IOException;
import java.net.*;

public class Main {

    public static void main(String[] args) throws IOException {

        final Pcap pcap = Pcap.openStream("C:\\Users\\n.hans\\Desktop\\VMFDatafromCORE.pcap");
        InetAddress group = InetAddress.getByName("239.5.192.4");
        MulticastSocket socket = new MulticastSocket(1581);
        socket.joinGroup(group);


        pcap.loop(new PacketHandler() {

            @Override
            public boolean nextPacket(Packet packet) throws IOException {

                if (packet.hasProtocol(Protocol.TCP)) {

                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    Buffer buffer = tcpPacket.getPayload();
                    if (buffer != null) {
                        System.out.println("TCP: " + buffer);
                    }
                } else if (packet.hasProtocol(Protocol.UDP)) {

                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    if (udpPacket.getDestinationPort() == 1581) {
                        Buffer buffer = udpPacket.getPayload();

                        if (buffer != null) {
                            byte[] payload = buffer.getArray();
                            DatagramPacket msg = new DatagramPacket(payload, payload.length,
                                    group, 1581);
                            socket.send(msg);


                        }
                    }


                }
                return true;
            }
        });
        socket.close();
    }
}