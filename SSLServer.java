package network;

 /*
** Configuring an extensible SSL server program;
* ****************************************************
* The listening port and address should be set by the User of the program\\
* The key for configuring this server program properties is com.sslserver
 */

import java.io.*;
import java.net.*;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.cert.*;
import java.security.*;
import javax.net.ssl.*;
import java.nio.channels.*;
import java.util.*;

/*
** The server has to run on its own thread after starting
 */

public class SSLServer implements  Runnable {

    private boolean serverConfigured = false;
    private SSLContext sslContext;
    private final Selector selector;
    private int PORT;
    private String host;


    public SSLServer() throws IOException{
        selector = Selector.open();
    }

/*
** The method has to be called first before the server start
*  it performs initial jsse configurations, uploading certificate provided
 */


    synchronized public void configureServer(Properties props)

    throws IOException, GeneralSecurityException

    {
        File keystoreFile = new File(props.getProperty("com.sslServer.keyStoreFile"));
        sslContext = SSLContext.getInstance("TLS");
        SecureRandom secureRandom = new SecureRandom();

        //
        secureRandom.nextInt();

        if (!keystoreFile.exists())
            throw new KeyStoreException("The key doesn't exist in the path!");

        // beginning actual jsse configuration;

        KeyStore privateKeyStore = KeyStore.getInstance("pkcs12");
        privateKeyStore.load(new FileInputStream(keystoreFile),props.getProperty("com.sslServer.keyStorePassword").toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(privateKeyStore,props.getProperty("com.sslServer.keyStorePassword").toCharArray());
        sslContext.init(kmf.getKeyManagers(),null,secureRandom);

        System.out.println("server configured!");  // give the user feedback upon terminating configuration
        serverConfigured= true;                   // The server is configured set serverConfigured true

    }


/*
** after all configuration has been set, now the user should start server
*  won't start unless it is perfectly configured
 */
    synchronized public void startServer(int PORT, String host)
            throws IOException
    {
        Thread serverThread = new Thread(this);
        this.host=host;
        this.PORT=PORT;

        //for later use by other methods in the class
        if (! serverConfigured)
            throw new ServerNotConfiguredException("Server was not properly configured");

        //
        SocketAddress socketAddress = new InetSocketAddress(InetAddress.getByName(host),PORT);
        channelConfiguration(socketAddress);
        serverThread.start();

    }


    private void channelConfiguration(SocketAddress socketAddress) throws IOException {
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.socket().bind(socketAddress);
        serverSocketChannel.register(selector,SelectionKey.OP_ACCEPT);

    }

    //

    @Override
    public void run()
    {

        System.out.println("Server started...");
        final long TIMEOUT = 120 * 1000; // wait for two minutes

       while (selector.keys().size()>0){  //If at least one channel is registered
/*
** Now the selector has to listen for each registered channel
*  any channel which is ready for operation is selected;
*  To manage server resources the channel has to listen up to TIMEOUT
 */

           try{
              int count=selector.select(TIMEOUT);

              if(count<=0)
              {
                  System.out.println();
                  System.out.println("Oops, Sever timeout!");
                  System.out.println("Make sure there is a device ready to connect to the sever");
                  continue;

                  //no channel is ready for operation!
              }

              for(SelectionKey selectedKey: selector.selectedKeys()){
                  if (!selectedKey.isValid())
                      continue;

                  if (selectedKey.isAcceptable()){
                      acceptConnection(selectedKey);

                  }

                  if(selectedKey.isReadable()){
                      readOperation(selectedKey);
                      selectedKey.cancel();
                  }

                  selector.selectedKeys().remove(selectedKey);

              }

           }

           catch(IOException e){
               System.out.println("Error Establishing connection with server!");
               System.exit(1);
           }
       }

    }

    //

    private void acceptConnection(SelectionKey sk)

    throws IOException
    {
        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) sk.channel();
        SocketChannel socketChannel = serverSocketChannel.accept();
        SSLEngine sslEngine =sslContext.createSSLEngine(host,PORT);
        SSLEncryptionManager manager = new SSLEncryptionManager(socketChannel,sslEngine);

        if (socketChannel!=null){


            System.out.println("Connected!");
            System.out.println();
            socketChannel.configureBlocking(false);
            socketChannel.register(selector,SelectionKey.OP_READ,manager);

        }
    }


    private void readOperation(SelectionKey sk){
        SSLEncryptionManager mgr = (SSLEncryptionManager) sk.attachment();
        byte[] text = new byte[mgr.getMinBufferSize()];

        try{
            mgr.read(text);
        }
        catch (IOException e){
            System.out.println("A client tried connected but couldn't maintain the session" +
                    "\n please verify the client's configuration or modify the server Security policy!");
            e.printStackTrace();
        }

        String message = new String(text);
        System.out.println(message);

        sk.interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
        writeOperation(sk);

    }

    private void writeOperation(SelectionKey sk){

    }


}



class ServerNotConfiguredException extends SSLException

{
    ServerNotConfiguredException(String exceptionMessage){

        super(exceptionMessage);
    }
}

/*
* This class will be used for managing the ssl sessions
* sending and receiving bytes from the channel;
* it performs internal encryption before sending the text buffers
* and also decrypt the text after receiving
* all of this is done on the host side:
 */

class SSLEncryptionManager {

    final private ByteBuffer sendPlainBuffer;
    final private ByteBuffer sendEncryptBuffer;
    final private ByteBuffer recvPlainBuffer;
    final private ByteBuffer recvEncryptBuffer;
    final private SSLSession sslSession;
    final private SSLEngine sslEngine;
    final private SocketChannel socketChannel;
    private SSLEngineResult sslEngineResult;
    private boolean handShakePerformed = false;


/*
* A constructor to initialize the necessary variables
 */
    SSLEncryptionManager(SocketChannel socketChannel, SSLEngine sslEngine){


        this.sslEngine = sslEngine;
        this.socketChannel = socketChannel;
        //
        sslEngine.setEnableSessionCreation(true);

        sslSession = sslEngine.getSession();

        int plainTextBufferSize = sslSession.getApplicationBufferSize();
        int encryptedTextBufferSize = sslSession.getPacketBufferSize();

        sendPlainBuffer = ByteBuffer.allocate(plainTextBufferSize);
        sendEncryptBuffer = ByteBuffer.allocate(encryptedTextBufferSize);
        recvEncryptBuffer = ByteBuffer.allocate(encryptedTextBufferSize);
        recvPlainBuffer = ByteBuffer.allocate(plainTextBufferSize);
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(true);
        sslEngine.setWantClientAuth(true);
    }

    /*
    * beginning the handshake to verify the session
    * if the handshake result is not agreed on either side
    * the established session should be canceled (invalidated)
     */

    private void handleHandshake() throws IOException
    {
        sslEngine.beginHandshake();

        X509Certificate[] certificate = (X509Certificate[]) sslSession.getPeerCertificates();

        try {
            certificate[0].checkValidity();
        }
        catch(GeneralSecurityException e){
            System.out.println("The certificate Expired");

            sslSession.invalidate();
            socketChannel.close();
            sslEngine.closeInbound();
            sslEngine.closeOutbound();

            return;
        }


        if(sslSession.isValid()){
            sslEngine.setEnabledCipherSuites(sslEngine.getEnabledCipherSuites());
            sslEngine.setEnabledProtocols(sslEngine.getEnabledProtocols());
            handShakePerformed=true;
        }

    }


    /*
    The read method should be called to read from the channel
    the method only responds if the handshake is completed!
     */

    public void read(byte[] byteArray) throws IOException

    {
        handleHandshake();

        if(!handShakePerformed)
            return;

        recvEncryptBuffer.rewind();
        socketChannel.read(recvEncryptBuffer);
        recvEncryptBuffer.flip();

        sslEngineResult = sslEngine.unwrap(recvEncryptBuffer,recvPlainBuffer);
        recvEncryptBuffer.clear();

        recvPlainBuffer.flip();

        switch(sslEngineResult.getStatus())
        {
            case BUFFER_OVERFLOW :
                throw new BufferOverflowException();

            case BUFFER_UNDERFLOW :
                throw new BufferUnderflowException();

            case CLOSED :
                throw new SSLException("Reading from the closed Engine!");

            case OK :
                break;
        }

        recvPlainBuffer.get(byteArray);
    }

    /*
    * The write method has to be called as a server response to a client
    * likewise, it only responds if the handshake completes!
     */

    public void write(byte[] byteArray) throws IOException
    {
        handleHandshake();
        if(!handShakePerformed)
            return;

        sendPlainBuffer.rewind();

        if (byteArray.length<=0)
            return;

        sendPlainBuffer.put(byteArray);
        sendPlainBuffer.flip();

        switch(sslEngine.wrap(sendPlainBuffer,sendEncryptBuffer).getStatus())
        {

            case BUFFER_OVERFLOW :
                throw new BufferOverflowException();

            case BUFFER_UNDERFLOW :
                throw new BufferUnderflowException();

            case CLOSED :
                throw new SSLException("writing to the closed Engine!");

            case OK :
                break;
        }

        sendPlainBuffer.clear();

        sendEncryptBuffer.flip();
        socketChannel.write(sendEncryptBuffer);
    }

    public int getMinBufferSize(){
       return sslSession.getApplicationBufferSize();
    }

    //

}