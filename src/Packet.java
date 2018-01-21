public class Packet {
    private String direction;
    private String protocol;
    private int port;
    private String ip;

    public Packet(String direction, String protocol, int port, String ip) {
        this.direction = direction;
        this.protocol = protocol;
        this.port = port;
        this.ip = ip;
    }

    public static class Builder {
        private String direction;
        private String protocol;
        private int port;
        private String ip;

        public Builder withDirection(String direction) {
            this.direction = direction;
            return this;
        }

        public Builder withProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder withPort(int port) {
            this.port = port;
            return this;
        }

        public Builder withIp(String ip) {
            this.ip = ip;
            return this;
        }

        public Packet build() {
            return new Packet(direction, protocol, port, ip);
        }
    }

    public String getDirection() { return this.direction;}

    public String getIp() { return this.ip;}

    public int getPort() { return this.port;}

    public String getProtocol() { return this.protocol;}

    @Override
    public boolean equals(Object o1)
    {
        Packet packet = (Packet)o1;
        if((this.direction.equals(packet.getDirection()))
                && this.ip.equals(packet.getIp())
                && (this.port == (packet.getPort()))
                && this.protocol.equals(packet.getProtocol()))
        {
            return true;
        }
        return false;
    }
}
