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
<<<<<<< HEAD
    private Boolean checkARPRequestReceive = false;
=======
    private static LayerManager m_LayerMgr = new LayerManager();

>>>>>>> 26c8dfa0a5a4ce782945065c996beeb5f8eb18b1
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

    private byte[] ObjToByte() {
        byte[] buf = new byte[28];
        
        buf[0] = m_sHeader.hardware_type[0];
        buf[1] = m_sHeader.hardware_type[1];
        buf[2] = m_sHeader.protocol_type[0];
        buf[3] = m_sHeader.protocol_type[1];
        buf[4] = m_sHeader.hardware_addr_len;
        buf[5] = m_sHeader.protocol_addr_len;
        buf[6] = m_sHeader.opcode[0];
        buf[7] = m_sHeader.opcode[1];
        buf[8] = m_sHeader.src_mac_addr.addr[0];
        buf[9] = m_sHeader.src_mac_addr.addr[1];
        buf[10] = m_sHeader.src_mac_addr.addr[2];
        buf[11] = m_sHeader.src_mac_addr.addr[3];
        buf[12] = m_sHeader.src_mac_addr.addr[4];
        buf[13] = m_sHeader.src_mac_addr.addr[5];
        buf[14] = m_sHeader.src_ip_addr.addr[0];
        buf[15] = m_sHeader.src_ip_addr.addr[1];
        buf[16] = m_sHeader.src_ip_addr.addr[2];
        buf[17] = m_sHeader.src_ip_addr.addr[3];
        buf[18] = m_sHeader.dst_mac_addr.addr[0];
        buf[19] = m_sHeader.dst_mac_addr.addr[1];
        buf[20] = m_sHeader.dst_mac_addr.addr[2];
        buf[21] = m_sHeader.dst_mac_addr.addr[3];
        buf[22] = m_sHeader.dst_mac_addr.addr[4];
        buf[23] = m_sHeader.dst_mac_addr.addr[5];
        buf[24] = m_sHeader.dst_ip_addr.addr[0];
        buf[25] = m_sHeader.dst_ip_addr.addr[1];
        buf[26] = m_sHeader.dst_ip_addr.addr[2];
        buf[27] = m_sHeader.dst_ip_addr.addr[3];
        
        return buf;
    }

    public boolean Send(byte[] input, int length) {

        String dst_addr = getDstIPAddr(input);
        if (!cacheTable.containsKey(dst_addr)) {
        	// ARP Request
        	String[] token = dst_addr.split("\\.");
            m_sHeader.dst_ip_addr.addr[0] = (byte) Integer.parseInt(token[0]);
            m_sHeader.dst_ip_addr.addr[1] = (byte) Integer.parseInt(token[1]);
            m_sHeader.dst_ip_addr.addr[2] = (byte) Integer.parseInt(token[2]);
            m_sHeader.dst_ip_addr.addr[3] = (byte) Integer.parseInt(token[3]);
        	m_sHeader.opcode[0] = 0x00;
        	m_sHeader.opcode[1] = 0x01;
        	
        	byte[] msg = ObjToByte();
        	GetUnderLayer().Send(msg, msg.length);
<<<<<<< HEAD
        	// Receive Dst Mac Address by ARP Request
        	while(checkARPRequestReceive) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        	// Load Dst Mac Address from cache table
            cacheTable.get(getDstIPAddr(input));
=======
        	
>>>>>>> 26c8dfa0a5a4ce782945065c996beeb5f8eb18b1
        }
        
        return true;
    }

    public synchronized boolean Receive(byte[] input) {
    	
    	if(input[6] == 0x00 && input[7] == 0x01) { // ARP request

    		// Update if there is no address pair on the table
    		String ip_toUdate = getSrcIPAddr(input);
    		if (!cacheTable.containsKey(ip_toUdate)) {
    			
    			String mac_toUpate = getSrcMACAddr(input);
    			cacheTable.put(ip_toUdate, mac_toUpate);

    			// Show the cache table to update
    			//
    		}
    		
    		// Send again by swapping str address and dst address
    		// Make a new frame 
    		m_sHeader.dst_ip_addr.addr[0] = input[14];		
            m_sHeader.dst_ip_addr.addr[1] = input[15];
            m_sHeader.dst_ip_addr.addr[2] = input[16];
            m_sHeader.dst_ip_addr.addr[3] = input[17];
            m_sHeader.dst_mac_addr.addr[0] = input[8];
            m_sHeader.dst_mac_addr.addr[1] = input[9];
            m_sHeader.dst_mac_addr.addr[2] = input[10];
            m_sHeader.dst_mac_addr.addr[3] = input[11];
            m_sHeader.dst_mac_addr.addr[4] = input[12];
            m_sHeader.dst_mac_addr.addr[5] = input[13];
            m_sHeader.opcode[0] = 0x00;
            m_sHeader.opcode[1] = 0x02;

            byte[] msg = ObjToByte();
    		GetUnderLayer().Send(msg, msg.length);		// Ethernet Layer
        	return true;

    	}
    	else if(input[6] == 0x00 && input[7] == 0x02) {
    
    		// Update if there is no address pair on the table
    		String ip_toUdate = getSrcIPAddr(input);		
    		if (!cacheTable.containsKey(ip_toUdate)) {
    			
    			String mac_toUpate = getSrcMACAddr(input);
    			cacheTable.put(ip_toUdate, mac_toUpate);
	
    			// Show Updated Cache Table
    			//
    		}

    		return true;
    	}else
    		return false;
    	
    }

    private String getDstIPAddr(byte[] input) { // from IP frame
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
    
    private String getSrcIPAddr(byte[] input) { // from APR frame
        byte[] addr = new byte[4];
        String ipAddrStr = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 14];

        ipAddrStr += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
            ipAddrStr += ".";
            ipAddrStr += Byte.toUnsignedInt(addr[j]);
        }

        return ipAddrStr;
    }
    
    private String getSrcMACAddr(byte[] input) { // from ARP frame
        byte[] addr = new byte[6];
        String macAddrStr = new String();

        for (int i = 0; i < 6; ++i)
            addr[i] = input[i + 8];

        macAddrStr += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 6; ++j) {
        	macAddrStr += ":";
        	macAddrStr += String.format("%02X", Byte.toUnsignedInt(addr[j]));
        }

        return macAddrStr;
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
