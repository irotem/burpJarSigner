package burp;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import static burp.JarSignerHelper.SignJar;


public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener
{


    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks)
    {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = this.callbacks.getHelpers();

        this.callbacks.setExtensionName("Name");
        this.callbacks.registerHttpListener(this);
        this.callbacks.registerProxyListener(this);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
//        stdout.println(
//                (messageIsRequest ? "Proxy request to " : "Proxy response from ") +
//                        message.getMessageInfo().getHttpService());

        IHttpRequestResponse messageInfo = message.getMessageInfo();
        String url = messageInfo.getUrl().getPath();
        if (url.length() <= 5)
        {
            return;
        }

        String extension = url.substring(url.length() - 4);
        if (extension.equals(".jar"))
        {
            stdout.println("path: " + url);
            byte[] response = messageInfo.getResponse();
            stdout.println("Length of request = " + response.length);
            IResponseInfo info = helpers.analyzeResponse(response);
            if (info.getStatusCode() == 200)
            {
                byte[] body = Arrays.copyOfRange(response, info.getBodyOffset(), response.length);
                stdout.println("Length of body = " + body.length + " offset = " + info.getBodyOffset());
                File temp = null;
                try {
                    temp = File.createTempFile("jarsigner-", ".tmp");
                    stdout.println(temp.getCanonicalPath());
                    FileOutputStream fos = new FileOutputStream(temp);
                    fos.write(body);
                    fos.close();
                    String signed_file = SignJar(temp, stdout);
                    Path path = Paths.get(signed_file);
                    byte[] newbody = Files.readAllBytes(path);

                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
                    response = Arrays.copyOfRange(response, 0, info.getBodyOffset());
                    outputStream.write(response,0,info.getBodyOffset());
                    outputStream.write(newbody);
                    outputStream.toByteArray();
                    messageInfo.setResponse(outputStream.toByteArray());

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            //write it


            stdout.println("Done");

        }
    }


}
