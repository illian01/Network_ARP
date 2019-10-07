package arp_test;


import java.util.ArrayList;
import java.util.StringTokenizer;


public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();


	private class _IP {		// HEADER + data 
		_IP_ADDR ip_src;
		_IP_ADDR ip_dst;
		
		byte ip_verlen;
		byte ip_tos;
		byte[] ip_len;
		byte[] ip_id;
		byte[] ip_fragoff;
		byte ip_ttl;
		byte ip_proto;
		byte[] ip_cksum;
		byte[] ip_data;
		
		public _IP() {
			this.ip_src =  new _IP_ADDR();
			this.ip_dst = new _IP_ADDR();
			
			this.ip_verlen = 0x00;
			this.ip_tos = 0x00;
			this.ip_len = new byte[2];
			this.ip_id = new byte[2];
			this.ip_fragoff = new byte[2];
			this.ip_ttl = 0x00;
			this.ip_proto = 0x00;
			ip_cksum = new byte[2];
			this.ip_data = null;
		}
		
		private class _IP_ADDR {
			private byte[] addr = new byte[6];
			
			public _IP_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
			}
		}
		
	}

	_IP m_sHeader = new _IP();

	public IPLayer(String pName) {
		
		pLayerName = pName;
		ResetHeader();
	}

	public void ResetHeader() {
		
		for (int i = 0; i < 4; i++) {
			m_sHeader.ip_src.addr[i] =  0x00;
			m_sHeader.ip_dst.addr[i] =  0x00;
		}
		
		m_sHeader.ip_verlen = 0x00;
		m_sHeader.ip_tos = 0x00;
		m_sHeader.ip_len[0] = 0x00;
		m_sHeader.ip_len[1] = 0x00;
		m_sHeader.ip_id[0] = 0x00;
		m_sHeader.ip_id[1] = 0x00;
		m_sHeader.ip_fragoff[0] = 0x00;
		m_sHeader.ip_fragoff[1] = 0x00;
		m_sHeader.ip_ttl = 0x00;
		m_sHeader.ip_proto = 0x00;
		m_sHeader.ip_data = null;
	}

	public byte[] ObjToByte(_IP Header, byte[] input, int length) {
		byte[] buf = new byte[length + 20];

		buf[0] = Header.ip_verlen;
		buf[1] = Header.ip_tos;
		buf[2] = Header.ip_len[0];
		buf[3] = Header.ip_len[1];
		buf[4] = Header.ip_id[0];
		buf[5] = Header.ip_id[1];
		buf[6] = Header.ip_fragoff[0];
		buf[7] = Header.ip_fragoff[1];
		buf[8] = Header.ip_ttl;
		buf[9] = Header.ip_proto;
		buf[10] = Header.ip_cksum[0];
		buf[11] = Header.ip_cksum[1];
		
		for (int i = 0; i < 4; i++)
			buf[12 + i] = Header.ip_src.addr[i];
		
		for (int i = 0; i < 4; i++)
			buf[16 + i] = Header.ip_dst.addr[i];

		for (int i = 0; i < length; i++)
			buf[20 + i] = input[i];

		return buf;
	}

	public boolean Send(byte[] input, int length) {

		byte[] send = ObjToByte(m_sHeader, input, length);
		p_UnderLayer.Send(send, send.length); // ARP

		return true;
	}
	

	public byte[] RemoveIPHeader(byte[] input, int length) {
		byte[] buf = new byte[length - 20];

		for (int i = 20; i < length; i++)
			buf[i-20] = input[i];

		return buf;
	}

	public synchronized boolean Receive(byte[] input) {

		byte[] data = RemoveIPHeader(input, input.length);
		this.GetUpperLayer(0).Receive(data); // TCP
		return true;
	}
	
	
	public void SetIP_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, ".");
		
		for(int i = 0; i < 4; i++)
			m_sHeader.ip_src.addr[i] = (byte) Integer.parseInt(st.nextToken());
	}
	
	public void SetIP_srcaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, ".");
		
		for(int i = 0; i < 4; i++)
			m_sHeader.ip_src.addr[i] = (byte) Integer.parseInt(st.nextToken());
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


}