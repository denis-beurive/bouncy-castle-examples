package org.beurive;

public class Packet {

    public static String dump_header(byte[] in_header) {
        StringBuilder result = new StringBuilder();

        if (in_header.length < 1) {
            result.append("Invalid header (it should contain at least 1 byte).");
            return result.toString();
        }
        int first_byte = (in_header[0] & 0b10000000) >> 7;
        boolean new_format = 1 == ((in_header[0] & 0b01000000) >> 6);
        int packet_tag = 0;

        StringBuilder format = new StringBuilder();
        if (new_format) {
            packet_tag = in_header[0] & 0b00111111;
            format.append(String.format("Tag: %d\n", packet_tag));
        } else {
            packet_tag = (in_header[0] & 0b00111100) >> 2;
            format.append(String.format("Tag: %d\n", packet_tag));
            int length_type = in_header[0] & 0b00000011;
            switch (length_type) {
                case 0: {
                    int payload_length = in_header[1];
                    format.append("The packet has a one-octet length. The header is 2 octets long. Length of the payload: " + payload_length + "\n");
                }; break;
                case 1: {
                    int payload_length = (in_header[1] << 8) + in_header[2];
                    format.append("The packet has a two-octet length. The header is 3 octets long. Length of the payload: " + payload_length + "\n");
                }; break;
                case 2: {
                    int payload_length = (in_header[1] << 24) + (in_header[2] << 16) + (in_header[3] << 8) + in_header[4];
                    format.append("The packet has a four-octet length. The header is 5 octets long. Length of the payload: " + payload_length + "\n");
                }; break;
                case 3: {
                    format.append("The packet is of indeterminate length.\n");
                }; break;
                default: {
                    result.append("Invalid header (unexpected packet length for old packet format).\n");
                    return result.toString();
                }
            }
        }

        result.append(String.format("First byte: %d\n", first_byte));
        result.append(String.format("New format? %s\n", new_format ? "yes" : "no"));
        result.append(format.toString());
        return result.toString();
    }

}
