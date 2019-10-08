package arp_test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    private Map<String, String> cacheTable = new HashMap<>();

    private _ARP_Packet m_sHeader = new _ARP_Packet();

    private class _ARP_Packet {
        _MAC_ADDR src_mac_addr;
        _MAC_ADDR dst_mac_addr;
        _IP_ADDR src_ip_addr;
        _IP_ADDR dst_ip_addr;

        byte[] hardware_type;
        byte[] protocol_type;
        byte hardware_addr_len;
        byte protocol_addr_len;
        byte[] opcode;
		byte[] arp_data;

        public _ARP_Packet() {
            src_mac_addr = new _MAC_ADDR();
            dst_mac_addr = new _MAC_ADDR();
            src_ip_addr = new _IP_ADDR();
            dst_ip_addr = new _IP_ADDR();

            hardware_type = new byte[2];
            protocol_type = new byte[2];
            hardware_addr_len = (byte) 0x00;
            protocol_addr_len = (byte) 0x00;
            opcode = new byte[2];
            arp_data = null;
        }

        private class _MAC_ADDR {
            private byte[] addr = new byte[6];

            public _MAC_ADDR() {
                this.addr[0] = (byte) 0x00;
                this.addr[1] = (byte) 0x00;
                this.addr[2] = (byte) 0x00;
                this.addr[3] = (byte) 0x00;
                this.addr[4] = (byte) 0x00;
                this.addr[5] = (byte) 0x00;
            }
        }

        private class _IP_ADDR {
            private byte[] addr = new byte[4];

            public _IP_ADDR() {
                this.addr[0] = (byte) 0x00;
                this.addr[1] = (byte) 0x00;
                this.addr[2] = (byte) 0x00;
                this.addr[3] = (byte) 0x00;
            }
        }

    }

    public ARPLayer(String pName) {
        pLayerName = pName;
        setHeader();
    }

    public void setHeader() {
        m_sHeader.hardware_type[0] = (byte) 0x00;
        m_sHeader.hardware_type[1] = (byte) 0x01;
        m_sHeader.protocol_type[0] = (byte) 0x08;
        m_sHeader.protocol_type[1] = (byte) 0x00;
        m_sHeader.hardware_addr_len = (byte) 0x06;
        m_sHeader.protocol_addr_len = (byte) 0x04;
        m_sHeader.opcode[0] = (byte) 0x00;
        m_sHeader.opcode[1] = (byte) 0x01;
        m_sHeader.dst_mac_addr.addr[0] = (byte) 0xFF;
        m_sHeader.dst_mac_addr.addr[1] = (byte) 0xFF;
        m_sHeader.dst_mac_addr.addr[2] = (byte) 0xFF;
        m_sHeader.dst_mac_addr.addr[3] = (byte) 0xFF;
        m_sHeader.dst_mac_addr.addr[4] = (byte) 0xFF;
        m_sHeader.dst_mac_addr.addr[5] = (byte) 0xFF;
    }

    public byte[] GenARPMsgHeader() {
        byte[] ARPMsgHeader = new byte[28];

        ARPMsgHeader[0] = m_sHeader.hardware_type[0];
        ARPMsgHeader[1] = m_sHeader.hardware_type[1];
        ARPMsgHeader[2] = m_sHeader.protocol_type[0];
        ARPMsgHeader[3] = m_sHeader.protocol_type[1];
        ARPMsgHeader[4] = m_sHeader.hardware_addr_len;
        ARPMsgHeader[5] = m_sHeader.protocol_addr_len;
        ARPMsgHeader[6] = m_sHeader.opcode[0];
        ARPMsgHeader[7] = m_sHeader.opcode[1];
        ARPMsgHeader[8] = m_sHeader.src_mac_addr.addr[0];
        ARPMsgHeader[9] = m_sHeader.src_mac_addr.addr[1];
        ARPMsgHeader[10] = m_sHeader.src_mac_addr.addr[2];
        ARPMsgHeader[11] = m_sHeader.src_mac_addr.addr[3];
        ARPMsgHeader[12] = m_sHeader.src_mac_addr.addr[4];
        ARPMsgHeader[13] = m_sHeader.src_mac_addr.addr[5];
        ARPMsgHeader[14] = m_sHeader.src_ip_addr.addr[0];
        ARPMsgHeader[15] = m_sHeader.src_ip_addr.addr[1];
        ARPMsgHeader[16] = m_sHeader.src_ip_addr.addr[2];
        ARPMsgHeader[17] = m_sHeader.src_ip_addr.addr[3];
        ARPMsgHeader[18] = m_sHeader.dst_mac_addr.addr[0];
        ARPMsgHeader[19] = m_sHeader.dst_mac_addr.addr[1];
        ARPMsgHeader[20] = m_sHeader.dst_mac_addr.addr[2];
        ARPMsgHeader[21] = m_sHeader.dst_mac_addr.addr[3];
        ARPMsgHeader[22] = m_sHeader.dst_mac_addr.addr[4];
        ARPMsgHeader[23] = m_sHeader.dst_mac_addr.addr[5];
        ARPMsgHeader[24] = m_sHeader.dst_ip_addr.addr[0];
        ARPMsgHeader[25] = m_sHeader.dst_ip_addr.addr[1];
        ARPMsgHeader[26] = m_sHeader.dst_ip_addr.addr[2];
        ARPMsgHeader[27] = m_sHeader.dst_ip_addr.addr[3];

        return ARPMsgHeader;
    }

    private byte[] GenARPRequestHeader() {
        m_sHeader.dst_mac_addr.addr[0] = (byte)0xff;
		m_sHeader.dst_mac_addr.addr[1] = (byte)0xff;
		m_sHeader.dst_mac_addr.addr[2] = (byte)0xff;
		m_sHeader.dst_mac_addr.addr[3] = (byte)0xff;
		m_sHeader.dst_mac_addr.addr[4] = (byte)0xff;
		m_sHeader.dst_mac_addr.addr[5] = (byte)0xff;

		byte[] ARPRequestHeader = GenARPMsgHeader();

        return ARPRequestHeader;
    }

    private byte[] ObjToByte(int dataLength) {
        byte[] buf = new byte[dataLength + 28];
        byte[] header = GenARPMsgHeader();

        for(int index = 0; index < 28; ++index) {
        	buf[index] = header[index];
		}

        for(int index = 0; index < dataLength; ++index) {
        	buf[index + 28] = m_sHeader.arp_data[index];
		}

        return buf;
    }

    public boolean Send(byte[] input, int length) {
        String dst_addr = getDstIPAddr(input);
        if (!cacheTable.containsKey(dst_addr)) {
        	// Can communication when the ip addr exist in cache
            String[] token = dst_addr.split(".");
            m_sHeader.dst_ip_addr.addr[0] = (byte) Integer.parseInt(token[0]);
            m_sHeader.dst_ip_addr.addr[1] = (byte) Integer.parseInt(token[1]);
            m_sHeader.dst_ip_addr.addr[2] = (byte) Integer.parseInt(token[2]);
            m_sHeader.dst_ip_addr.addr[3] = (byte) Integer.parseInt(token[3]);
			m_sHeader.arp_data = input;
        } else {
			// Need for implementing that ARP Request

			// Need for implementing that receive mac addr and set mac addr

        }
        // Send part(Common part)
		byte[] msg = ObjToByte(input.length);
		GetUnderLayer().Send(msg, msg.length);

        return true;
    }

    public synchronized boolean Receive(byte[] input) {
        return true;
    }

    private String getDstIPAddr(byte[] input) {
        byte[] addr = new byte[4];
        String ipAddrStr = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 12];

        ipAddrStr += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
            ipAddrStr += ".";
            ipAddrStr += Byte.toUnsignedInt(addr[j]);
        }

        return ipAddrStr;
    }


    @Override
    public String GetLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        // TODO Auto-generated method stub
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
        // nUpperLayerCount++;

    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }

    public void SetMAC_dstaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, "-");

        for (int i = 0; i < 6; i++)
            m_sHeader.dst_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);

    }

    public void SetMAC_srcaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, "-");

        for (int i = 0; i < 6; i++)
            m_sHeader.src_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);

    }

    public void SetIP_dstaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, ".");

        for (int i = 0; i < 4; i++)
            m_sHeader.dst_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
    }

    public void SetIP_srcaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, ".");

        for (int i = 0; i < 4; i++)
            m_sHeader.src_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
    }


}