package arp_test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JList;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    private Boolean checkARPRequestReceive = false;

    public boolean changeMacAddress = false;
    private Map<String, String> cacheTable = new HashMap<>();
    private Map<String, String> ProxyARPCacheTable = new HashMap<>();

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
        m_sHeader.dst_mac_addr.addr[0] = (byte) 0x00;
        m_sHeader.dst_mac_addr.addr[1] = (byte) 0x00;
        m_sHeader.dst_mac_addr.addr[2] = (byte) 0x00;
        m_sHeader.dst_mac_addr.addr[3] = (byte) 0x00;
        m_sHeader.dst_mac_addr.addr[4] = (byte) 0x00;
        m_sHeader.dst_mac_addr.addr[5] = (byte) 0x00;
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

		if (changeMacAddress) {
			
			// Send GARP request
			m_sHeader.dst_ip_addr.addr[0] = m_sHeader.src_ip_addr.addr[0];
			m_sHeader.dst_ip_addr.addr[1] = m_sHeader.src_ip_addr.addr[1];
			m_sHeader.dst_ip_addr.addr[2] = m_sHeader.src_ip_addr.addr[2];
			m_sHeader.dst_ip_addr.addr[3] = m_sHeader.src_ip_addr.addr[3];
			m_sHeader.dst_mac_addr.addr[0] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[1] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[2] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[3] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[4] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[5] = (byte) 0x00;
			m_sHeader.opcode[0] = 0x00;
			m_sHeader.opcode[1] = 0x01;

			byte[] msg = ObjToByte();
			GetUnderLayer().Send(msg, msg.length);
			changeMacAddress = false;
			

			// Receive Dst Mac Address by GARP Request
			checkARPRequestReceive = false;
			int count = 0;
			while (!checkARPRequestReceive) { // GARP Reply check
				try {
					Thread.sleep(10000);
					++count;
					GetUnderLayer().Send(msg, msg.length); // Resend
					if (count == 10) {
						return true;						// no reply ?? 
					}
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}

			return true;
		}
        
        String dstIP_addr = getDstIPAddrFromIPFrame(input);
        if (!cacheTable.containsKey(dstIP_addr)) {

			// Send ARP Request
			String[] token = dstIP_addr.split("\\.");
			m_sHeader.dst_ip_addr.addr[0] = (byte) Integer.parseInt(token[0]);
			m_sHeader.dst_ip_addr.addr[1] = (byte) Integer.parseInt(token[1]);
			m_sHeader.dst_ip_addr.addr[2] = (byte) Integer.parseInt(token[2]);
			m_sHeader.dst_ip_addr.addr[3] = (byte) Integer.parseInt(token[3]);
			m_sHeader.dst_mac_addr.addr[0] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[1] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[2] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[3] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[4] = (byte) 0x00;
			m_sHeader.dst_mac_addr.addr[5] = (byte) 0x00;
			m_sHeader.opcode[0] = 0x00;
			m_sHeader.opcode[1] = 0x01;

			byte[] msg = ObjToByte();
			GetUnderLayer().Send(msg, msg.length);

			// Receive Dst Mac Address by ARP Request
			checkARPRequestReceive = false;
			int count = 0;
			while (!checkARPRequestReceive) { // ARP Reply check
				try {
					Thread.sleep(10000);
					++count;
					GetUnderLayer().Send(msg, msg.length); // Resend
					if (count == 10) {
						return false;
					}
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}

		}

        // Load Dst Mac Address from cache table
        String dstMacAddr = cacheTable.get(dstIP_addr);
        
        // Set Dst Mac address to Ethernet Header
        ((EthernetLayer)GetUnderLayer()).Setenet_dstaddr(dstMacAddr);
        
        synchronized (this) {
        	if(input.length == 48) {
        		try {
					wait();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
        	}
		}

        GetUnderLayer().Send(input, input.length);
        
        return true;
    }

    public synchronized boolean Receive(byte[] input) {
    	if(!isValidIPAddr(input) && !isValidMACAddr(input)) return false;
    	else if(isValidMACAddr(input)) {
    		
    		if(input[6] == 0x00 && input[7] == 0x01) {
    			// Receive GARP request
        		// check IP collision 
        		if(checkIPCollision(input)) {
        			
        			// send GARP reply
        			m_sHeader.dst_ip_addr.addr[0] = input[14];
                    m_sHeader.dst_ip_addr.addr[1] = input[15];
                    m_sHeader.dst_ip_addr.addr[2] = input[16];
                    m_sHeader.dst_ip_addr.addr[3] = input[17];
                    m_sHeader.dst_mac_addr.addr[0] = 0x00;
                    m_sHeader.dst_mac_addr.addr[1] = 0x00;
                    m_sHeader.dst_mac_addr.addr[2] = 0x00;
                    m_sHeader.dst_mac_addr.addr[3] = 0x00;
                    m_sHeader.dst_mac_addr.addr[4] = 0x00;
                    m_sHeader.dst_mac_addr.addr[5] = 0x00;
                    m_sHeader.opcode[0] = 0x00;
                    m_sHeader.opcode[1] = 0x02;

                    byte[] msg = ObjToByte();
                    GetUnderLayer().Send(msg, msg.length);        // Ethernet Layer
                    return true;
        		}

        		
        		String srcIPAddr_rev = getSrcIPAddrFromARPFrame(input);
                String srcMacAddr_rev = getSrcMACAddrFromARPFrame(input);

                // Update if there is no address pair on the table
                if (!cacheTable.containsKey(srcIPAddr_rev)) {

                	cacheTable.put(srcIPAddr_rev, srcMacAddr_rev);
                    updateCacheTableGUI();		// Show the cache table to update - Need for implement
                }
                // Update the value if there is address pair on the table
                else {

                	cacheTable.replace(srcIPAddr_rev, srcMacAddr_rev);
                    updateCacheTableGUI();		// Show the cache table to update - Need for implement
                }
                
                return true;
    		}
    		else if(input[6] == 0x00 && input[7] == 0x02) {
    			// Receive GARP reply
    			System.out.println("** IP COLLISION Occurred **");
        		checkARPRequestReceive = true; // ARP Reply check
        		
        		return true;
    		}
    	}
    	else {
    		
    		if(input[6] == 0x00 && input[7] == 0x01) {
    			// Receive GARP request
    			String srcIPAddr_rev = getSrcIPAddrFromARPFrame(input);
                String srcMacAddr_rev = getSrcMACAddrFromARPFrame(input);
                String dstIPAddr_rev = getDstIPAddrFromARPFrame(input);
                
                // Update if there is no address pair on the table
                if (!cacheTable.containsKey(srcIPAddr_rev)) {
                	
                    cacheTable.put(srcIPAddr_rev, srcMacAddr_rev);
                    updateCacheTableGUI();		// Show the cache table to update - Need for implement
                }
                
                if(checkDstIPAddr(input)) {		
                	
                	// This ARP request is mine
                    // Send again by swapping str address and dst address
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
                    GetUnderLayer().Send(msg, msg.length);        // Ethernet Layer
                    return true;
                	
                }
                else if(ProxyARPCacheTable.containsKey(dstIPAddr_rev)){

                	// This ARP request is not mine 
                    // Check Proxy cache table 
            		byte[] srcIP_tmp = new byte[4];
            		
            		srcIP_tmp[0] = m_sHeader.src_ip_addr.addr[0]; // my real ip addr
            		srcIP_tmp[1] = m_sHeader.src_ip_addr.addr[1];
            		srcIP_tmp[2] = m_sHeader.src_ip_addr.addr[2];
            		srcIP_tmp[3] = m_sHeader.src_ip_addr.addr[3];

            		m_sHeader.src_ip_addr.addr[0] = input[24]; // src
            		m_sHeader.src_ip_addr.addr[1] = input[25];
            		m_sHeader.src_ip_addr.addr[2] = input[26];
            		m_sHeader.src_ip_addr.addr[3] = input[27];
            		m_sHeader.dst_ip_addr.addr[0] = input[14]; // dst
            		m_sHeader.dst_ip_addr.addr[1] = input[15];
            		m_sHeader.dst_ip_addr.addr[2] = input[16];
            		m_sHeader.dst_ip_addr.addr[3] = input[17];
            		m_sHeader.dst_mac_addr.addr[0] = m_sHeader.src_mac_addr.addr[0];
            		m_sHeader.dst_mac_addr.addr[1] = m_sHeader.src_mac_addr.addr[1];
            		m_sHeader.dst_mac_addr.addr[2] = m_sHeader.src_mac_addr.addr[2];
            		m_sHeader.dst_mac_addr.addr[3] = m_sHeader.src_mac_addr.addr[3];
            		m_sHeader.dst_mac_addr.addr[4] = m_sHeader.src_mac_addr.addr[4];
            		m_sHeader.dst_mac_addr.addr[5] = m_sHeader.src_mac_addr.addr[5];
            		m_sHeader.opcode[0] = 0x00;
            		m_sHeader.opcode[1] = 0x02;

            		byte[] msg = ObjToByte();
            		GetUnderLayer().Send(msg, msg.length);        // Ethernet Layer
            		
            		// Set src_ip to real address
            		m_sHeader.src_ip_addr.addr[0] = srcIP_tmp[0]; 
            		m_sHeader.src_ip_addr.addr[1] = srcIP_tmp[1];
            		m_sHeader.src_ip_addr.addr[2] = srcIP_tmp[2];
            		m_sHeader.src_ip_addr.addr[3] = srcIP_tmp[3];
            		
            		return true;
                }
    		}
    		else if(input[6] == 0x00 && input[7] == 0x02) {
    			// Receive GARP reply
    			// Update cache Table
                String srcIPAddr_rev = getSrcIPAddrFromARPFrame(input);
                String srcMacAddr_rev = getSrcMACAddrFromARPFrame(input);
                if(!cacheTable.containsKey(srcIPAddr_rev)) {
                	
                    cacheTable.put(srcIPAddr_rev, srcMacAddr_rev);
                    updateCacheTableGUI();		// Show the cache table to update - Need for implement
                }
                
                checkARPRequestReceive = true; // ARP Reply check
                
                synchronized(this) {
                	notifyAll();
                }
                return true;
    		}
    	}
        return false;
    }
    
    
    
    public void updateCacheTableGUI() {
    	
    	ARPDlg GUI = (ARPDlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0);
    	
    	DefaultListModel<String> model = new DefaultListModel<>();
    	for(String str : cacheTable.keySet()) {
    		String append = str + "    " + cacheTable.get(str) + "    complete";
    		model.addElement(append);
    	}
    	GUI.ARPCacheList.setModel(model);
    }
    
    public void updateProxyARPCacheTableGUI() {
    	
    	ARPDlg GUI = (ARPDlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0);
    	
    	DefaultListModel<String> model = new DefaultListModel<>();
    	for(String str : ProxyARPCacheTable.keySet()) {
    		String append = str + "        " + ProxyARPCacheTable.get(str);
    		model.addElement(append);
    	}
    	GUI.ProxyARPEntryList.setModel(model);
    }
    
    public void addProxyARPCacheTable(String ipAddr, String macAddr) {
    	
    	// input format is xxx.xxx.xxx.xxx and XX:XX:XX:XX:XX:XX
        if (!ProxyARPCacheTable.containsKey(ipAddr)) {
        	ProxyARPCacheTable.put(ipAddr, macAddr);
        }
    }
	
	private boolean checkIPCollision(byte[] input) {

		// input is ARP frame
		// If the dst_ip of the input and my IP are the same, collision  
		for (int i = 0; i < 4; i++)
			if (m_sHeader.src_mac_addr.addr[i] != input[i + 24])
				return true;

		return false;
	}

    private boolean isValidIPAddr(byte[] input) {
    	
        // if src ip equal to my ip -> return false
        for(int i = 0; i < 4; i++)
            if(m_sHeader.src_ip_addr.addr[i] != input[i+14])
                return true;

        return false;
    }
    
    private boolean isValidMACAddr(byte[] input) {
    	
    	// if src mac equal my mac -> return false
    	for(int i = 0; i < 6; i++)
    		if(m_sHeader.src_mac_addr.addr[i] != input[i+8])
    			return true;
    	
    	return false;
    }

    private boolean checkDstIPAddr(byte[] input) {
    	   
    	// Dst ip is equal to my ip --> 1
       	for (int i = 0; i < 4; i++) { 
    		if(m_sHeader.src_ip_addr.addr[i] != input[i+24])  break;
			if(i == 5) return true;
		 }
       	
       	// Src ip and Dst ip is not equal to my ip
        return false;
    }
    
    private String getDstIPAddrFromIPFrame(byte[] input) { // from IP frame
    	
        byte[] addr = new byte[4];
        String ipAddrStr = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 16];

        ipAddrStr += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
            ipAddrStr += ".";
            ipAddrStr += Byte.toUnsignedInt(addr[j]);
        }

        return ipAddrStr;
    }
    
    private String getDstIPAddrFromARPFrame(byte[] input) { // from ARP frame
    	
        byte[] addr = new byte[4];
        String ipAddrStr = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 24];

        ipAddrStr += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
            ipAddrStr += ".";
            ipAddrStr += Byte.toUnsignedInt(addr[j]);
        }

        return ipAddrStr;
    }
    
    private String getSrcIPAddrFromARPFrame(byte[] arp_header) { // from APR frame
    	
        byte[] addr = new byte[4];
        String ipAddrStr = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = arp_header[i + 14];

        ipAddrStr += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
            ipAddrStr += ".";
            ipAddrStr += Byte.toUnsignedInt(addr[j]);
        }

        return ipAddrStr;
    }

    private String getSrcMACAddrFromARPFrame(byte[] arp_header) { // from ARP frame
    	
        byte[] addr = new byte[6];
        String macAddrStr = new String();

        for (int i = 0; i < 6; ++i)
            addr[i] = arp_header[i + 8];

        macAddrStr += String.format("%02X", Byte.toUnsignedInt(addr[0]));
        for (int j = 1; j < 6; ++j) {
            macAddrStr += "-";
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

    public void removeCache(String ipAddr) {
    	cacheTable.remove(ipAddr);
    	updateCacheTableGUI();
    }
    
    public void removeCacheAll() {
    	cacheTable = new HashMap<>();
    	updateCacheTableGUI();
    }
    
    public void removeProxyARPCache(String ipAddr) {
    	ProxyARPCacheTable.remove(ipAddr);
    	updateCacheTableGUI();
    }
    
    public void ChangeMacAddress() {
    	this.changeMacAddress = true;
    }

}
