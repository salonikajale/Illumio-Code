public class Main {
    public static void main(String[] args){
        Firewall firewall = new Firewall("/Users/Saloni/IdeaProjects/Illumio/src/firewallrules.csv");
        System.out.println(firewall.accept_packet("inbound", "tcp",80,"192.168.1.2"));
        System.out.println(firewall.accept_packet("outbound", "tcp",10089,"192.168.10.11"));
        System.out.println(firewall.accept_packet("inbound", "udp",53,"192.168.2.4"));
        System.out.println(firewall.accept_packet("inbound", "udp",53,"192.168.1.254"));
        System.out.println(firewall.accept_packet("inbound", "tcp",53,"192.168.1.254"));
    }
}
