/*
This program will communicate using socket 8080 and sending SNMP trap version 1 and version 2 to client (MyClient_Socket.java).

Name: Mohammad Ariff Bin Idris
ID: 2017430762
Subject: Test 3 ITT786
Dateline: 18 November 2018
*/
package myserver_socket;

import java.io.IOException;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.MessageException;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.StateReference;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.TransportIpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.tools.console.SnmpRequest;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;



    
public class MyServer_Socket implements CommandResponder
{
  public MyServer_Socket()
  {
  }

  public static void main(String[] args)
  {
    MyServer_Socket snmp4jTrapReceiver = new MyServer_Socket();
    try
    {
      snmp4jTrapReceiver.listen(new UdpAddress("localhost/8080"));
    }
    catch (IOException e)
    {
      System.err.println("Error in Listening for Trap");
      System.err.println("Exception Message = " + e.getMessage());
    }
  }

  /**
   * Dengar perangkap dan memberi maklumbalas melalui agen SNMP
   */
  public synchronized void listen(TransportIpAddress address) throws IOException
  {
    AbstractTransportMapping transport;
    if (address instanceof TcpAddress)
    {
      transport = new DefaultTcpTransportMapping((TcpAddress) address);
    }
    else
    {
      transport = new DefaultUdpTransportMapping((UdpAddress) address);
    }

    ThreadPool threadPool = ThreadPool.create("DispatcherPool", 10);
    MessageDispatcher mtDispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

    // tambah mesej memproses model
    mtDispatcher.addMessageProcessingModel(new MPv1());
    mtDispatcher.addMessageProcessingModel(new MPv2c());

    // tambah sekuriti protocol
    SecurityProtocols.getInstance().addDefaultProtocols();
    SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

    //Buat sasaran
    CommunityTarget target = new CommunityTarget();
    target.setCommunity( new OctetString("public"));
    
    Snmp snmp = new Snmp(mtDispatcher, transport);
    snmp.addCommandResponder(this);
    
    transport.listen();
    System.out.println("Listening on " + address +"\n");

    try
    {
      this.wait();
    }
    catch (InterruptedException ex)
    {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Ia akan berfungsi apabila terdapat panggilan melalui PDU kepada port tertentu yang di dengar
   */
  public synchronized void processPdu(CommandResponderEvent cmdRespEvent)
  {
    System.out.println("\n"+"Received PDU...");
    PDU pdu = cmdRespEvent.getPDU();
    if (pdu != null)
    {

      System.out.println("Trap Type = " + pdu.getType());
      System.out.println("Variable Bindings = " + pdu.getVariableBindings());
      
      
      int pduType = pdu.getType();
      if ((pduType != PDU.TRAP) && (pduType != PDU.V1TRAP) && (pduType != PDU.REPORT)
      && (pduType != PDU.RESPONSE))
      {
        pdu.setErrorIndex(0);
        pdu.setErrorStatus(0);
        pdu.setType(PDU.RESPONSE);
        StatusInformation statusInformation = new StatusInformation();
        StateReference ref = cmdRespEvent.getStateReference();
        try
        {
          System.out.println(cmdRespEvent.getPDU());
          cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
          cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
          pdu, cmdRespEvent.getMaxSizeResponsePDU(), ref, statusInformation);
        }
        catch (MessageException ex)
        {
          System.err.println("Error while sending response: " + ex.getMessage());
          LogFactory.getLogger(SnmpRequest.class).error(ex);
        }
      }
    }
  }
}
