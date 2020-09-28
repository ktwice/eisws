package eisfile;

import java.io.*;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.xml.namespace.QName;
import javax.xml.soap.*;
import javax.xml.stream.*;

/**
 *
 * @author ktwice
 */
public class Eisws2 implements AutoCloseable {
    static protected final Charset UTF8 = Charset.forName("UTF-8");

    protected final Map<String,String> nss = new TreeMap<>();
    protected final Map<String,String> services = new TreeMap<>();
    protected  MessageFactory mf;
    protected  SOAPConnectionFactory cf;
    protected  SOAPConnection connection;
    
    public Eisws2() {
        try {
            mf = MessageFactory.newInstance();
            cf = SOAPConnectionFactory.newInstance();
            connection = cf.createConnection();
        } catch (SOAPException ex) {
            System.out.println(ex.getMessage());
        }
    }
    @Override
    public void close() {
        try {
            connection.close();
        } catch (SOAPException ex) {
            System.out.println(ex.getMessage());
        }
    }
    public  void nssPut(String name, String addr) {
        nss.put(name, addr);
    }
    public  void servicesPut(String name, String addr) {
        if(name == null)
            name = addr.substring(1 + addr.lastIndexOf("/"));
        services.put(name, addr);
    }
    public SOAPMessage newRequest(String operation, Map<String, String> in_map)
            throws SOAPException, Exception {
        SOAPMessage m = mf.createMessage();
        setSOAPHeader(m.getSOAPHeader());
        setSOAPBody(m.getSOAPBody(), operation, in_map);
        m.saveChanges();
        return m;
    }
    public SOAPMessage callRespond(SOAPMessage request, String service)
            throws SOAPException {
        return connection.call(request, services.get(service));
    }
    protected void setSOAPBody(SOAPBody mb, String operation, Map<String, String> in_map)
            throws SOAPException {
        String[] es = operation.split(":");
        SOAPElement e = es.length>1
            ? mb.addChildElement(es[1], es[0], nss.get(es[0]))
            : mb.addChildElement(es[0]);
        for(Map.Entry<String, String> me: in_map.entrySet()) {
            e.addChildElement(me.getKey()).addTextNode(me.getValue());
        }
    }
    static public void main(String[] args)
            throws XMLStreamException, FileNotFoundException {
        final String xname = args[0]; 
        final String xprefix = xname.substring(1
            + Math.max(xname.lastIndexOf("/"), xname.lastIndexOf("\\"))) + "-";
    try (Eisws2 eis2 = new Eisws2()) {
        final XMLInputFactory xf = XMLInputFactory.newInstance();
        final XMLStreamReader xsr = xf.createXMLStreamReader(
            new FileInputStream(xname));
    try {
        xsr.nextTag();
        System.out.println(xname + " <" + xsr.getLocalName()+"> root element.");
        while(xsr.nextTag() == XMLStreamReader.START_ELEMENT) {
            String tag = xsr.getLocalName();
            switch(tag) {
                case "ns":
                    eis2.nssPut(xsr.getAttributeValue(null, "name")
                        , xsr.getAttributeValue(null, "addr"));
                    if(xsr.nextTag() == XMLStreamReader.START_ELEMENT)
                        throw new Exception("tag=ns has unexpected child");
                    break;
                case "service":
                    String name = xsr.getAttributeValue(null, "name");
                    String addr = xsr.getAttributeValue(null, "addr");
                    eis2.servicesPut(name, addr);
                    if(xsr.nextTag() == XMLStreamReader.START_ELEMENT)
                        throw new Exception("tag=service has unexpected child");
                    break;
                case "out":
    String fname = xsr.getAttributeValue(null, "fname");
    System.out.print(fname);
    String service = xsr.getAttributeValue(null, "service");
    String operation = xsr.getAttributeValue(null, "operation");
    Map<String, String> in_map = new TreeMap<>();
    while(xsr.nextTag() == XMLStreamReader.START_ELEMENT) {
        if(!xsr.getLocalName().equals("in"))
            throw new Exception("unexpected tag="+xsr.getLocalName()+". Hope <in>");
        in_map.put(xsr.getAttributeValue(null, "name")
            , xsr.getElementText());
    }
    SOAPMessage request = eis2.newRequest(operation, in_map);
    SOAPMessage respond = eis2.callRespond(request, service);
    try (OutputStream xml = new FileOutputStream(xprefix + fname + ".xml")) {
        xml.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".getBytes(UTF8));
        xml.write("\n<out><request>\n".getBytes(UTF8));
        request.getSOAPHeader().detachNode(); // without access codes
        request.saveChanges();
        request.writeTo(xml);
        xml.write("\n</request><respond>\n".getBytes(UTF8));
        respond.writeTo(xml);
        xml.write("\n</respond></out>\n".getBytes(UTF8));
        System.out.println(" completed.");
    }
                    break;
                default: throw new Exception("unknown tag="+tag+" in root");
            }
        }
        System.out.println("That's all.");         
    } catch(Exception e) {
        System.out.println(e.getMessage());
    } finally {
        xsr.close();
    }
    }
    }
    static protected void setSOAPHeader(SOAPHeader header)
        throws SOAPException, Exception {
        final String DOCS_WSS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-";
        final SimpleDateFormat SDF_UTC =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
        SDF_UTC.setTimeZone(TimeZone.getTimeZone("UTC"));

        Date d = new Date();
        header.addNamespaceDeclaration("wsse"
            , DOCS_WSS + "wssecurity-secext-1.0.xsd");
        header.addNamespaceDeclaration("wsu"
            , DOCS_WSS + "wssecurity-utility-1.0.xsd");
        SOAPElement security = header.addChildElement("Security", "wsse");

        SOAPElement ut = security.addChildElement("UsernameToken", "wsse");
        ut.addChildElement("Username", "wsse").setTextContent(getEnv("eiswsu"));
        SOAPElement p = ut.addChildElement("Password", "wsse");
        p.addAttribute(new QName("Type")
            , DOCS_WSS + "username-token-profile-1.0#PasswordText");
        p.setTextContent(getEnv("eiswsp"));
        SOAPElement n = ut.addChildElement("Nonce", "wsse");
        n.addAttribute(new QName("EncodingType")
            , DOCS_WSS + "soap-message-security-1.0#Base64Binary");
        n.setTextContent(getNonce());
        ut.addChildElement("Created", "wsu").setTextContent(SDF_UTC.format(d));
        
        SOAPElement ts = security.addChildElement("Timestamp", "wsu");
        d = new Date();
        ts.addChildElement("Created", "wsu").setTextContent(SDF_UTC.format(d));
        d = new Date(d.getTime() + 60000 * 60 * 6); // six hours!
        ts.addChildElement("Expires", "wsu").setTextContent(SDF_UTC.format(d));
    }
    static protected String getNonce() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(System.currentTimeMillis());
        return Base64.getEncoder().encodeToString(sr.generateSeed(16));
    }
    static protected String getEnv(String ename) throws Exception {
        String s = System.getenv(ename);
        if(s != null) return s;
        throw new Exception(ename + " environment variable not exists!");
    }
    
}
