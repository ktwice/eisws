import java.io.*;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.xml.namespace.QName;
import javax.xml.soap.*;
import javax.xml.stream.*;

/**
 * Execute requests to EIS SOAP-services
 * @author k2-adm
 */
public class Eisws {
/**
 * Run requests and save results
 * @param args args[0] xml-file with requests
 */    
    public static void main(String[] args) {
        final Map<String,String> nss = new TreeMap<>();
        final Map<String,String> services = new TreeMap<>();
        final String xname = args[0]; 
        final String xprefix = xname.substring(1
            + Math.max(xname.lastIndexOf("/"), xname.lastIndexOf("\\"))) + "-";
    try {
        final MessageFactory mf = MessageFactory.newInstance();
        final SOAPConnectionFactory cf = SOAPConnectionFactory.newInstance();
        final SOAPConnection connection = cf.createConnection();
        final XMLInputFactory xf = XMLInputFactory.newInstance();
        final XMLStreamReader xsr = xf.createXMLStreamReader(
            new FileInputStream(xname));
        xsr.nextTag();
        System.out.println(xname + " <" + xsr.getLocalName()+"> root element.");
        while(xsr.nextTag() == XMLStreamReader.START_ELEMENT) {
            String tag = xsr.getLocalName();
            switch(tag) {
                case "ns":
                    nss.put(xsr.getAttributeValue(null, "name")
                        , xsr.getAttributeValue(null, "addr"));
                    if(xsr.nextTag() == XMLStreamReader.START_ELEMENT)
                        throw new Exception("tag=ns has unexpected child");
                    break;
                case "service":
                    String addr = xsr.getAttributeValue(null, "addr");
                    String name = xsr.getAttributeValue(null, "name");
                    if(name==null) name = addr.substring(1 + addr.lastIndexOf("/"));
                    services.put(name, addr);
                    if(xsr.nextTag() == XMLStreamReader.START_ELEMENT)
                        throw new Exception("tag=service has unexpected child");
                    break;
                case "out":
    String service = xsr.getAttributeValue(null, "service");
    String fname = xsr.getAttributeValue(null, "fname");
    SOAPMessage m = newMessage(mf);
    String[] es = xsr.getAttributeValue(null, "operation").split(":");
    SOAPElement e = es.length>1
        ? m.getSOAPBody().addChildElement(es[1], es[0], nss.get(es[0]))
        : m.getSOAPBody().addChildElement(es[0]);
    while(xsr.nextTag() == XMLStreamReader.START_ELEMENT)
        e.addChildElement(xsr.getAttributeValue(null, "name"))
            .addTextNode(xsr.getElementText());
    m.saveChanges();
    xmlOut(xprefix + fname + ".xml", m
        , connection.call(m, services.get(service)));
                    break;
                default: throw new Exception("unknown tag="+tag+" in root");
            }
        }
        xsr.close();
        connection.close();
        System.out.println("That's all.");         
    } catch(Exception e) {
        System.out.println(e.getMessage());
    }
    }
/**
 * Save request and response to xml-file
 * @param fname xml-filename 
 * @param request SOAP request-message
 * @param respond SOAP respond-message
 */    
    protected static void xmlOut(String fname
    , SOAPMessage request
    , SOAPMessage respond) throws SOAPException, IOException {
        final Charset UTF8 = Charset.forName("UTF-8");
        System.out.print(fname);
        try (OutputStream xml = new FileOutputStream(fname)) {
            xml.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".getBytes(UTF8));
            xml.write("\n<out><request>\n".getBytes(UTF8));
            request.getSOAPHeader().detachNode(); // without access codes
            request.saveChanges();
            request.writeTo(xml);
            xml.write("\n</request><respond>\n".getBytes(UTF8));
            respond.writeTo(xml);
            xml.write("\n</respond></out>\n".getBytes(UTF8));
        }
        System.out.println(" completed.");
    }
/**
 * Completely fill header for just-created SOAP request-message
 * @param mf SOAPMessage factory
 * @return just-created SOAP request-message
 */    
    static protected SOAPMessage newMessage(MessageFactory mf)
        throws SOAPException, Exception {
        final String DOCS_WSS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-";
        final SimpleDateFormat SDF_UTC =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
        SDF_UTC.setTimeZone(TimeZone.getTimeZone("UTC"));

        Date d = new Date();
        SOAPMessage message = mf.createMessage();
        SOAPHeader header = message.getSOAPHeader();
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
        d = new Date(d.getTime() + 60000); // 0ne minute!
        ts.addChildElement("Expires", "wsu").setTextContent(SDF_UTC.format(d));
        return message;
    }
/**
 * Random value for Nonce-element
 * @return base64 text
 */    
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
