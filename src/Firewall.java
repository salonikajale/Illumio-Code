import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

public class Firewall {
    private String pathToFirewallCsv;
    private Map<String, List<Packet>> ipToPacketMap = new HashMap<>(); // Optimizes searching rule for a given IP.

    public Firewall(final String pathToFirewallCsv) {
        this.pathToFirewallCsv = pathToFirewallCsv;
        buildRuleList();
    }

    /**
     * Check if rule exists for forwarding the incoming packet.
     * @param direction
     * @param protocol
     * @param port
     * @param ip
     * @return
     */
    public boolean accept_packet(final String direction, final String protocol, final int port, final String ip) {
        Packet packet = buildFirewallRule(direction, protocol, port, ip);
        List<Packet> existingPacketList = ipToPacketMap.get(ip);
        if (existingPacketList.size() > 0) {
            return existingPacketList.contains(packet);
        }
        return false;
    }

    /**
     * Converts CSV file to a Map of IP and List of Packet object.
     * CSV -> Map<IP, List<Packet>
     */
    private void buildRuleList() {
        String line = "";
        String cvsSplitBy = ",";

        try (BufferedReader br = new BufferedReader(new FileReader(pathToFirewallCsv))) {

            while ((line = br.readLine()) != null) {

                // use comma as separator
                String[] rule = line.split(cvsSplitBy);


                //handle port range
                List<Integer> portRange = new LinkedList<>();
                String port = rule[2];
                if (port.contains("-")) {
                    portRange.addAll(getPortListFromRange(port));
                } else {
                    portRange.add(Integer.valueOf(port));
                }

                // handle ip range
                List<String> ipRange = new LinkedList<>();
                String ip = rule[3];
                if (ip.contains("-")) {
                    ipRange.addAll(getIpListFromRange(ip));
                } else {
                    ipRange.add(ip);
                }

                // Generate forwarding rule for every port and for every ip in a given range.
                portRange.forEach(p -> {
                    ipRange.forEach(i -> {
                        Packet packet = buildFirewallRule(rule[0], rule[1], p, i);
                        List<Packet> tempPacketList = new LinkedList<>();
                        if (ipToPacketMap.get(i) != null && ipToPacketMap.get(i).size() > 0) {
                            tempPacketList.addAll(ipToPacketMap.get(i));
                        }
                        tempPacketList.add(packet);
                        ipToPacketMap.put(i, tempPacketList);
                    });
                });
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate a list of port from a given port range
     * @param portRange
     * @return
     */
    private List<Integer> getPortListFromRange(final String portRange) {
        List<Integer> portList = new LinkedList<>();
        String[] ports = portRange.split("-"); // 10000-10050
        IntStream.range(Integer.valueOf(ports[0]), Integer.valueOf(ports[1])).forEach(i -> {
            portList.add(i);
        });
        return portList;
    }

    /**
     * Generate a List of IPs from a given IP range.
     * @param ipRange
     * @return
     */
    private List<String> getIpListFromRange(final String ipRange) {
        List<String> ipList = new LinkedList<>();
        String[] ips = ipRange.split("-");

        LongStream.range(ipToLong(ips[0]), ipToLong(ips[1])).forEach(i -> {
            ipList.add(longToIp(i));
        });

        return ipList;
    }

    /**
     * Convert a given IP address to a long representation (192.168.1.2 -> 3232235778)
     * @param ipAddress
     * @return
     */
    public long ipToLong(String ipAddress) {

        String[] ipAddressInArray = ipAddress.split("\\.");

        long result = 0;
        for (int i = 0; i < ipAddressInArray.length; i++) {

            int power = 3 - i;
            int ip = Integer.parseInt(ipAddressInArray[i]);
            result += ip * Math.pow(256, power);
        }
        return result;
    }

    /**
     * Convert long represnetation of a IP back to normal String representation (3232235778 -> 192.168.1.2)
     * @param ip
     * @return
     */
    public String longToIp(long ip) {
        StringBuilder result = new StringBuilder(15);

        for (int i = 0; i < 4; i++) {

            result.insert(0,Long.toString(ip & 0xff));

            if (i < 3) {
                result.insert(0,'.');
            }

            ip = ip >> 8;
        }
        return result.toString();
    }

    /**
     * Private builder for creating Packet object.
     * @param direction
     * @param protocol
     * @param port
     * @param ip
     * @return
     */
    private Packet buildFirewallRule(final String direction, final String protocol, final int port, final String ip) {
        return new Packet.Builder()
                .withDirection(direction)
                .withProtocol(protocol)
                .withPort(port)
                .withIp(ip)
                .build();
    }

}

