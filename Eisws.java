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
    protected static final Charset UTF8 = Charset.forName("UTF-8");
    protected static final String DOCS_WSS =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-";
    protected static final SimpleDateFormat SDF_UTC =
        new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
    static {
        SDF_UTC.setTimeZone(TimeZone.getTimeZone("UTC"));
    }
    protected static Map<String,String> nss = new TreeMap<>();
    protected static Map<String,String> services = new TreeMap<>();
/**
 * Run requests and save results
 * @param args args[0] xml-file with requests
 */    
    public static void main(String[] args) {
    try {
        SOAPConnectionFactory cf = SOAPConnectionFactory.newInstance();
        SOAPConnection connection = cf.createConnection();

        XMLInputFactory xf = XMLInputFactory.newInstance();
        XMLStreamReader xsr = xf.createXMLStreamReader(
                new FileInputStream(args[0]));
        xsr.nextTag();
        System.out.println(xsr.getLocalName()+" root element.");
        while(xsr.nextTag() == xsr.START_ELEMENT) {
            String tag = xsr.getLocalName();
            switch(tag) {
                case "ns":
                    nss.put(xsr.getAttributeValue(null, "name")
                            , xsr.getAttributeValue(null, "addr"));
                    if(xsr.nextTag() == xsr.START_ELEMENT)
                        throw new Exception("tag=ns has unexpected child");
                    break;
                case "service":
                    String addr = xsr.getAttributeValue(null, "addr");
                    String name = xsr.getAttributeValue(null, "name");
                    if(name==null) name = addr.substring(addr.lastIndexOf("/")+1);
                    services.put(name, addr);
                    if(xsr.nextTag() == xsr.START_ELEMENT)
                        throw new Exception("tag=service has unexpected child");
                    break;
                case "out":
                    String service = xsr.getAttributeValue(null, "service");
                    String fname = xsr.getAttributeValue(null, "fname");
                    SOAPMessage rq = wsRequest(xsr);
                    xmlOut(fname, rq, connection.call(rq, services.get(service)));
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
 * @param name xml-filename base-part
 * @param request SOAP request-message
 * @param respond SOAP respond-message
 */    
    protected static void xmlOut(String name
    , SOAPMessage request
    , SOAPMessage respond) throws SOAPException, IOException {
        String fname = "eis-" + name + ".xml";
        System.out.print(fname);
        try (OutputStream xml = new FileOutputStream(fname)) {
            xml.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".getBytes(UTF8));
            xml.write("\n<out><request>\n".getBytes(UTF8));
            request.writeTo(xml);
            xml.write("\n</request><respond>\n".getBytes(UTF8));
            respond.writeTo(xml);
            xml.write("\n</respond></out>\n".getBytes(UTF8));
        }
        System.out.println(" completed.");
    }
/**
 * Building SOAP request-message
 * @param xsr XMLStreamReader (out-element)
 * @return completed request-message
 */ 
    protected static SOAPMessage wsRequest(XMLStreamReader xsr
        ) throws SOAPException, IOException, XMLStreamException, Exception {
        MessageFactory mf = MessageFactory.newInstance();
        SOAPMessage m = mf.createMessage();
        String eiswsu = System.getenv("eiswsu");
        if(eiswsu==null) {
            System.out.println("eiswsu environment variable not exists!");
            System.exit(1);
        }
        wsHeader(m, eiswsu, System.getenv("eiswsp"));
        String[] oper = xsr.getAttributeValue(null, "operation").split(":");
        SOAPElement operation = oper.length>1
        ? m.getSOAPBody().addChildElement(oper[1], oper[0], nss.get(oper[0]))
        : m.getSOAPBody().addChildElement(oper[0]);
        while(xsr.nextTag() == xsr.START_ELEMENT) {
            String name = xsr.getAttributeValue(null, "name");
            String text = xsr.getElementText();
            operation.addChildElement(name).addTextNode(text);
        }
        m.saveChanges();
        return m;
    }
/**
 * Completely fill header for just-created SOAP request-message
 * @param message
 * @param username
 * @param password
 */    
    static protected void wsHeader(SOAPMessage message,
        final String username, final String password) throws SOAPException {
        SOAPHeader header = message.getSOAPHeader();
        Date d = new Date();
        header.addNamespaceDeclaration("wsse"
                , DOCS_WSS + "wssecurity-secext-1.0.xsd");
        header.addNamespaceDeclaration("wsu"
                , DOCS_WSS + "wssecurity-utility-1.0.xsd");
        SOAPElement security = header.addChildElement("Security", "wsse");

        SOAPElement ut = security.addChildElement("UsernameToken", "wsse");
        ut.addChildElement("Username", "wsse").setTextContent(username);
        SOAPElement p = ut.addChildElement("Password", "wsse");
        p.addAttribute(new QName("Type")
                , DOCS_WSS + "username-token-profile-1.0#PasswordText");
        p.setTextContent(password);
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

}
