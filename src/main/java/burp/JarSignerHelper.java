package burp;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import sun.security.tools.jarsigner.Main;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;


/**
 * Created by Rotem on 7/22/2016.
 */
public class JarSignerHelper
{

    private static final int keysize = 1024;
    private static final String commonName = "JarSignerCA";
    private static final String organizationalUnit = "IT";
    private static final String organization = "test";
    private static final String city = "test";
    private static final String state = "test";
    private static final String country = "US";
    private static final long validity = 1096; // 3 years
    private static final String alias = "tomcat";
    private static final char[] keyPass = "changeit".toCharArray();
    private static final String keystoreFile = ".keystore";

    private static boolean location_written = false;

    public static String SignJar(File jarfile, PrintWriter stdout) {
        String absolute_keystore = null;

        try {
            String jarFileNew = RemoveOldSignature(jarfile);

            File f = new File(keystoreFile);
            if(f.exists() && !f.isDirectory()) {
                absolute_keystore = f.getAbsolutePath();
            }
            else
            {
                absolute_keystore = generateKeyStore();
            }

            if (location_written == false)
            {
                stdout.println("LOCATION of keystore is in :" + absolute_keystore);
                location_written = true;
            }

            Main.main(new String[] {
                    "-keystore", absolute_keystore,
                    "-storepass", String.valueOf(keyPass),
                    jarFileNew,
                    alias
            });

            return jarFileNew;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    private static String RemoveOldSignature(File jarfile) throws IOException {
         /* Define ZIP File System Properies in HashMap */
        File temp = File.createTempFile("jarunsigned-", ".tmp");
        ZipFile zipFile = new ZipFile(jarfile);
        final ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(temp));
        for(Enumeration e = zipFile.entries(); e.hasMoreElements(); ) {
            ZipEntry entryIn = (ZipEntry) e.nextElement();
            String entry = entryIn.getName().toUpperCase();
            if ((entry.startsWith("META-INF"))
                    && (entry.endsWith(".RSA") || entry.endsWith(".SF") || entry.endsWith("MANIFEST.MF")))
            {
                if (entry.endsWith("MANIFEST.MF"))
                {

                    zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
                    InputStream is = zipFile.getInputStream(entryIn);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is));

                    String s;
                    boolean lastline_deleted = false;
                    while ((s = reader.readLine()) != null)
                    {
                        if (s.startsWith(" ") && lastline_deleted)
                        {
                            // DO NOTHING
                        }
                        else if (s.startsWith("Name:") || s.contains("Digest"))
                        {
                            lastline_deleted = true;
                        }
                        else if (!s.equals(""))
                        {
                            s += "\r\n";
                            zos.write(s.getBytes(),0, s.length());
                        }

                    }
                    zos.closeEntry();
                }
            }
            else
            {
                zos.putNextEntry(entryIn);
                InputStream is = zipFile.getInputStream(entryIn);
                byte[] buf = new byte[1024];
                int len;
                while((len = is.read(buf)) > 0) {
                    zos.write(buf, 0, len);
                }
                zos.closeEntry();
            }

        }
        zos.close();
        return temp.getAbsolutePath();
    }


    public static String generateKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            keyStore.load(null, null);

            CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);

            X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, city, state, country);

            keypair.generate(keysize);
            PrivateKey privKey = keypair.getPrivateKey();

            X509Certificate[] chain = new X509Certificate[1];

            chain[0] = keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);

            keyStore.setKeyEntry(alias, privKey, keyPass, chain);

            keyStore.store(new FileOutputStream(keystoreFile), keyPass);

            return (new File(keystoreFile).getAbsolutePath());
        }
        catch (Exception e)
        {
            return null;
        }
    }


    public static void main(String[] args) {
        File file = new File("C:\\Users\\Rotem\\AppData\\Local\\Temp\\" + "jarunsigned-6530323347838675390.tmp");

        SignJar(file, new PrintWriter(System.out));

    }
}
