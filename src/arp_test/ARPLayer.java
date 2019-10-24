package arp_test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import javax.swing.DefaultListModel;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    private Map<String, Entry> cacheTable = new HashMap<>();
    private Map<String, Entry> ProxyARPCacheTable = new HashMap<>();

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
        ARPRepeatThread thread = new ARPRepeatThread();
		Thread obj = new Thread(thread);
		obj.start();
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

    public synchronized boolean Send(byte[] input, int length) {
        String dstIP_addr = getDstIPAddrFromIP(input);
        String[] token = dstIP_addr.split("\\.");
        
        if(isGratuitousSend(input) || !cacheTable.containsKey(dstIP_addr)) {
        	
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
    		m_sHeader.opcode[1] = 0x01;
        	
			byte[] msg = ObjToByte();
			cacheTable.put(dstIP_addr, new Entry(dstIP_addr, "??-??-??-??-??-??", "incomplete"));
			updateCacheTableGUI();
			GetUnderLayer().Send(msg, msg.length);
        }
        
        if(length > 48) {
        	SendThread thread = new SendThread(dstIP_addr, input);
    		Thread obj = new Thread(thread);
    		obj.start();
        }
      
        return true;
    }

    public synchronized boolean Receive(byte[] input) {
    	
    	if(isGratuitous(input)) {
    		if(isResponse(input)) {
    			System.out.println("Collision!");
    		}
    		else if(isCollision(input)) {
    			byte[] response = input.clone();
    			response[7] = 0x02;
    			GetUnderLayer().Send(response, response.length);
    		}
    		else
    			updateCache(input);
    		
    		return true;
    	}
    	
    	
    	else {
    		updateCache(input);
    		if(isTargetMe(input)){
    			for(int i = 0; i < 6; i++)
    				m_sHeader.dst_mac_addr.addr[i] = input[8+i];
    			for(int i = 0; i < 4; i++)
    				m_sHeader.dst_ip_addr.addr[i] = input[14+i];
    			m_sHeader.opcode[1] = 0x02;
    			byte[] response = ObjToByte();
    			GetUnderLayer().Send(response, response.length);
    		}
    		else if(ProxyARPCacheTable.containsKey(getDstIPAddrFromARP(input))) {
    			for(int i = 0; i < 6; i++)
    				m_sHeader.dst_mac_addr.addr[i] = input[10+i];
    			for(int i = 0; i < 4; i++)
    				m_sHeader.dst_ip_addr.addr[i] = input[14+i];
    			m_sHeader.opcode[1] = 0x02;
    			byte[] response = ObjToByte();
    			response[14] = input[24];
    			response[15] = input[25];
    			response[16] = input[26];
    			response[17] = input[27];
    			GetUnderLayer().Send(response, response.length);
    		}
    		else return false;
    	}

        return true;
    }
    
    private synchronized void updateCache(byte[] input) {
    	String src_ip = getSrcIPAddrFromARP(input);
		String src_mac = getSrcMACAddrFromARP(input);
		this.cacheTable.put(src_ip, new Entry(src_ip, src_mac, "completed"));
		updateCacheTableGUI();
    }
    
    private boolean isTargetMe(byte[] input) {
    	for(int i = 0; i < 4; i++) {
    		if(input[24+i] != m_sHeader.src_ip_addr.addr[i]) break;
    		if(i == 3) return true;
    	}
    	
    	return false;
    }
    
    private boolean isResponse(byte[] input) {
    	return (input[6] == 0x00 && input[7] == 0x02);
    }
    
    private boolean isGratuitousSend(byte[] input) {
    	return getDstIPAddrFromIP(input).compareTo(getSrcIPAddrFromIP(input)) == 0;
    }
    
    
    private boolean isGratuitous(byte[] input) {
    	for(int i = 0; i < 4; i++) {
    		if(input[14+i] != input[24+i]) break;
    		if(i == 3) return true;
    	}
    	
    	return false;
    }
    
    private boolean isCollision(byte[] input) {
    	for(int i = 0; i < 4; i++) {
    		if(input[14+i] != m_sHeader.src_ip_addr.addr[i]) break;
    		if(i == 3) return true;
    	}
    	
    	return false;
    }
    
    private String getSrcIPAddrFromIP(byte[] input) {
    	byte[] addr = new byte[4];
        String addr_str = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 12];

        addr_str += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
        	addr_str += ".";
        	addr_str += Byte.toUnsignedInt(addr[j]);
        }

        return addr_str;
    }
    
    private String getDstIPAddrFromIP(byte[] input) {
        byte[] addr = new byte[4];
        String addr_str = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 16];

        addr_str += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
        	addr_str += ".";
        	addr_str += Byte.toUnsignedInt(addr[j]);
        }

        return addr_str;
    }
    
    private String getSrcIPAddrFromARP(byte[] input) {
    	byte[] addr = new byte[4];
        String addr_str = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 14];

        addr_str += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
        	addr_str += ".";
        	addr_str += Byte.toUnsignedInt(addr[j]);
        }

        return addr_str;
    }
    
    private String getDstIPAddrFromARP(byte[] input) {
    	byte[] addr = new byte[4];
        String addr_str = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 24];

        addr_str += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
        	addr_str += ".";
        	addr_str += Byte.toUnsignedInt(addr[j]);
        }

        return addr_str;
    }
    
	private String getSrcMACAddrFromARP(byte[] input) {
		byte[] addr = new byte[6];
        String addr_str = new String();

        for (int i = 0; i < 6; ++i)
            addr[i] = input[i + 8];

        addr_str += String.format("%02X", Byte.toUnsignedInt(addr[0]));
        for (int j = 1; j < 6; ++j) {
        	addr_str += "-";
        	addr_str += String.format("%02X", Byte.toUnsignedInt(addr[j]));
        }

        return addr_str;
	}
	
    public synchronized void updateCacheTableGUI() {
    	
    	ARPDlg GUI = (ARPDlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0);
    	
    	DefaultListModel<String> model = new DefaultListModel<>();
    	for(String str : cacheTable.keySet()) {
    		String append = str + "    " + cacheTable.get(str).mac + "    " + cacheTable.get(str).status;
    		model.addElement(append);
    	}
    	GUI.ARPCacheList.setModel(model);
    }
    
    public synchronized void updateProxyARPCacheTableGUI() {
    	
    	ARPDlg GUI = (ARPDlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0);
    	
    	DefaultListModel<String> model = new DefaultListModel<>();
    	for(String str : ProxyARPCacheTable.keySet()) {
    		String append = str + "        " + ProxyARPCacheTable.get(str).mac;
    		model.addElement(append);
    	}
    	GUI.ProxyARPEntryList.setModel(model);
    }
    
    public synchronized void addProxyARPCacheTable(String ipAddr, String macAddr) {
    	
    	// input format is xxx.xxx.xxx.xxx and XX:XX:XX:XX:XX:XX
        if (!ProxyARPCacheTable.containsKey(ipAddr)) {
        	ProxyARPCacheTable.put(ipAddr, new Entry(ipAddr, macAddr, "Proxy"));
        }
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

    public synchronized void SetMAC_dstaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, "-");

        for (int i = 0; i < 6; i++)
            m_sHeader.dst_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);

    }

    public synchronized void SetMAC_srcaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, "-");

        for (int i = 0; i < 6; i++)
            m_sHeader.src_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);

    }

    public synchronized void SetIP_dstaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, ".");

        for (int i = 0; i < 4; i++)
            m_sHeader.dst_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
    }

    public synchronized void SetIP_srcaddr(String address) {
        StringTokenizer st = new StringTokenizer(address, ".");

        for (int i = 0; i < 4; i++)
            m_sHeader.src_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
    }

    public synchronized void removeCache(String ipAddr) {
    	cacheTable.remove(ipAddr);
    	updateCacheTableGUI();
    }
    
    public synchronized void removeCacheAll() {
    	cacheTable = new HashMap<>();
    	updateCacheTableGUI();
    }
    
    public synchronized void removeProxyARPCache(String ipAddr) {
    	ProxyARPCacheTable.remove(ipAddr);
    	updateCacheTableGUI();
    }

    
    class ARPRepeatThread implements Runnable {

		public ARPRepeatThread() {}

		public void run() {
			while (true) {
				for(String str : cacheTable.keySet()) {
		    		Entry entry = cacheTable.get(str);
		    		if(entry.status == "completed") {
		    			if(System.currentTimeMillis() - entry.createdTime > 1200000) { // 1200000ms == 20 min
		    				removeCache(str);
		    			}
		    		}
		    		else if(entry.status == "incomplete") {
		    			if(entry.count == 3) {
		    				entry.status = "failed";
		    				updateCacheTableGUI();
		    			}
		    			else {
		    		        StringTokenizer st = new StringTokenizer(entry.ip, ".");
		    		        for (int i = 0; i < 4; i++)
		    		            m_sHeader.dst_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
		    	    		m_sHeader.dst_mac_addr.addr[0] = (byte) 0x00;
		    	    		m_sHeader.dst_mac_addr.addr[1] = (byte) 0x00;
		    	    		m_sHeader.dst_mac_addr.addr[2] = (byte) 0x00;
		    	    		m_sHeader.dst_mac_addr.addr[3] = (byte) 0x00;
		    	    		m_sHeader.dst_mac_addr.addr[4] = (byte) 0x00;
		    	    		m_sHeader.dst_mac_addr.addr[5] = (byte) 0x00;
		    	    		m_sHeader.opcode[1] = 0x01;
		    	        	
		    				byte[] msg = ObjToByte();
		    				entry.count++;
		    				updateCacheTableGUI();
		    				GetUnderLayer().Send(msg, msg.length);
		    			}
		    		}
		    	}
				
				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}
    
    class SendThread implements Runnable {
    	String dst_addr;
    	byte[] input;
    	
		public SendThread(String dst_addr, byte[] input) {
			this.dst_addr = dst_addr;
			this.input = input;
		}

		public void run() {
			while (cacheTable.containsKey(dst_addr)) {
				Entry entry = cacheTable.get(dst_addr);
				if(entry.status == "completed") {
					((EthernetLayer) GetUnderLayer()).Setenet_dstaddr(cacheTable.get(dst_addr).mac);
					GetUnderLayer().Send(input, input.length);
					break;
				}
				else if(entry.status == "failed") break;
			}
		}
		
	}
    
    class Entry {
    	String ip;
    	String mac;
    	String status;
    	int count;
    	long createdTime;
    	
    	public Entry(String ip, String mac, String status) {
    		this.ip = ip;
    		this.mac = mac;
    		this.status = status;
    		this.count = 0;
    		this.createdTime = System.currentTimeMillis();
    	}
    }
}
