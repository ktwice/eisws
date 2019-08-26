package eisws;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import javax.xml.namespace.QName;
import javax.xml.soap.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Execute requests to EIS SOAP-services
 * @author k2-adm
 */
public class Eisws {
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
 * Building SOAP request message
 * @param xsr XMLStreamReader (out-element)
 * @return completed request message
 * @throws SOAPException
 * @throws IOException
 * @throws XMLStreamException
 * @throws Exception 
 */ 
    protected static SOAPMessage eisRequest(XMLStreamReader xsr
        ) throws SOAPException, IOException, XMLStreamException, Exception {
        MessageFactory mf = MessageFactory.newInstance();
        SOAPMessage m = mf.createMessage();
        eisHeader(m, System.getenv("eiswsu"), System.getenv("eiswsp"));
        String[] oper = xsr.getAttributeValue(null, "operation").split(":");
        SOAPElement operation = oper.length>1
        ? m.getSOAPBody().addChildElement(oper[1], oper[0], nss.get(oper[0]))
        : m.getSOAPBody().addChildElement(oper[0]);
        while(xsr.nextTag() == xsr.START_ELEMENT) {
            String arg = xsr.getAttributeValue(null, "name");
            String text = xsr.getElementText();
            operation.addChildElement(arg).addTextNode(text);
        }
        m.saveChanges();
        return m;
    }
/**
 * Save request and response to xml-file
 * @param name xml-filename base
 * @param request request SOAP message
 * @param respond respond SOAP message
 * @throws SOAPException
 * @throws IOException 
 */    
    protected static void eisOut(String name
    , SOAPMessage request
    , SOAPMessage respond) throws SOAPException, IOException {
        String fname = "eis-" + name + ".xml";
        System.out.print(fname);
        Charset utf8 = Charset.forName("UTF-8");
        try (OutputStream xml = new FileOutputStream(fname)) {
            xml.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".getBytes(utf8));
            xml.write("\n<out><request>\n".getBytes(utf8));
            request.writeTo(xml);
            xml.write("\n</request><respond>\n".getBytes(utf8));
            respond.writeTo(xml);
            xml.write("\n</respond></out>\n".getBytes(utf8));
        }
        System.out.println(" completed.");
    }
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
            String addr;
            String tag = xsr.getLocalName();
            switch(tag) {
                case "ns":
                    nss.put(xsr.getAttributeValue(null, "name")
                            , xsr.getAttributeValue(null, "addr"));
                    if(xsr.nextTag() == xsr.START_ELEMENT)
                        throw new Exception("ns tag has unexpected child");
                    break;
                case "service":
                    addr = xsr.getAttributeValue(null, "addr");
                    String name = xsr.getAttributeValue(null, "name");
                    if(name==null) name = addr.substring(addr.lastIndexOf("/")+1);
                    services.put(name, addr);
                    if(xsr.nextTag() == xsr.START_ELEMENT)
                        throw new Exception("service tag has unexpected child");
                    break;
                case "out":
                    String service = xsr.getAttributeValue(null, "service");
                    addr = services.get(service);
                    String fname = xsr.getAttributeValue(null, "fname");
                    SOAPMessage request = eisRequest(xsr);
                    SOAPMessage respond = connection.call(request, addr);
                    eisOut(fname, request, respond);
                    break;
                default: throw new Exception("unknown tag="+tag+" in root");
            }
        }
        xsr.close();
        connection.close();
             
    } catch(Exception e) {
        System.out.println(e.getMessage());
    }
    }
/**
 * Fill header for SOAP message
 * @param message
 * @param username
 * @param password
 * @throws SOAPException 
 */    
    static protected void eisHeader(SOAPMessage message,
        final String username, final String password) throws SOAPException {
        SOAPHeader header = message.getSOAPHeader();
        if(username==null) {
            System.out.println("eiswsu environment variable not exists!");
            System.exit(1);
        }
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
