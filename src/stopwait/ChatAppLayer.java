package stopwait;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class ChatAppLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	public ByteBuffer buf = ByteBuffer.allocate(2048);

	private class _CHAT_APP {
		byte[] capp_totlen;
		byte capp_type;
		byte capp_unused;
		byte[] capp_data;

		public _CHAT_APP() {
			this.capp_totlen = new byte[2];
			this.capp_type = 0x00;
			this.capp_unused = 0x00;
			this.capp_data = new byte[10];
		}
	}

	_CHAT_APP m_sHeader = new _CHAT_APP();

	public ChatAppLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		ResetHeader();
	}

	public void ResetHeader() {
		for (int i = 0; i < 2; i++) {
			m_sHeader.capp_totlen[i] = (byte) 0x00;
		}
		m_sHeader.capp_data = null;
	}

	public byte[] ObjToByte(_CHAT_APP Header, byte[] input, int length) {
		byte[] buf = new byte[length + 4];

		buf[0] = Header.capp_totlen[0];
		buf[1] = Header.capp_totlen[1];
		buf[2] = Header.capp_type;
		buf[3] = Header.capp_unused;

		for (int i = 0; i < length; i++)
			buf[4 + i] = input[i];

		return buf;
	}

	public boolean Send(byte[] input, int length) {
		byte[] send;
		m_sHeader.capp_totlen[0] = (byte) (length/255);
		m_sHeader.capp_totlen[1] = (byte) (length%255);
		
		if(length > 10) {
			m_sHeader.capp_data = input;
			m_sHeader.capp_type = (byte) 0x01;
			m_sHeader.capp_unused = (byte) 0x00;
			byte[] buf = new byte[10];
			for(int i = 0; i < 10; i++) buf[i] = input[i];
			send = ObjToByte(m_sHeader, buf, 10);
			p_UnderLayer.Send(send, send.length);
			buf = new byte[length-10];
			for(int i = 10; i < length; i++) buf[i-10] = input[i];
			m_sHeader.capp_data = buf;
		}
		else {
			m_sHeader.capp_data = null;
			m_sHeader.capp_type = (byte) 0x00;
			m_sHeader.capp_unused = (byte) 0x00;
			send = ObjToByte(m_sHeader, input, length);
			p_UnderLayer.Send(send, send.length);
		}

		return true;
	}
	
	public boolean ack(byte[] input) {
		byte[] buf = new byte[4];
		buf[0] = input[0];
		buf[1] = input[1];
		buf[2] = (byte) 0x04;
		buf[3] = (byte) 0x00;
		
		p_UnderLayer.Send(buf, buf.length);
		
		return true;
	}
	
	public boolean send_next() {
		byte[] buf;
		byte[] send;
		
		if(m_sHeader.capp_data.length > 10) {
			m_sHeader.capp_type = (byte) 0x02;
			m_sHeader.capp_unused = (byte) 0x00;
			buf = new byte[10];
			for(int i = 0; i < 10; i++) buf[i] = m_sHeader.capp_data[i];
			send = ObjToByte(m_sHeader, buf, 10);
			p_UnderLayer.Send(send, send.length);
			buf = new byte[m_sHeader.capp_data.length-10];
			for(int i = 10; i < m_sHeader.capp_data.length; i++) buf[i-10] = m_sHeader.capp_data[i];
			m_sHeader.capp_data = buf;
		}
		else {
			m_sHeader.capp_type = (byte) 0x03;
			m_sHeader.capp_unused = (byte) 0x00;
			send = ObjToByte(m_sHeader, m_sHeader.capp_data, m_sHeader.capp_data.length);
			p_UnderLayer.Send(send, send.length);
			ResetHeader();
		}
		
		return true;
	}
	

	public byte[] RemoveCappHeader(byte[] input, int length) {
		byte[] buf = new byte[length - 4];

		for (int i = 4; i < length; i++)
			buf[i-4] = input[i];

		return buf;
	}

	public synchronized boolean Receive(byte[] input) {
		byte[] data;
		int type = input[2];
		
		data = RemoveCappHeader(input, input.length);
		switch(type) {
		case 0 :
			
			this.GetUpperLayer(0).Receive(trim_null(data));
			ack(input);
			break;
			
		case 1 :
		case 2 : 
			buf.put(trim_null(data));
			ack(input);
			break;
			
		case 3 :
			buf.put(trim_null(data));
			this.GetUpperLayer(0).Receive(buf.array());

			buf.clear();
			ack(input);
			break;
		case 4 :
			if((m_sHeader.capp_type != (byte) 0x00) && (m_sHeader.capp_data != null))
				send_next();
		}
		
		return true;
	}
	
	public byte[] trim_null(byte[] input) {
		byte[] buf;
		int i;
		
		for(i = 0; i < input.length; i++)
			if(input[i] == (byte) 0x00) break;
		
		buf = new byte[i];
		
		for(i = 0; i < buf.length; i++)
			buf[i] = input[i];
		
		return buf;
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
