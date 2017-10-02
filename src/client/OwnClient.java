package client;

import sertserver.OwnCert;

import javax.crypto.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Created by Тимур on 10.06.2017.
 */
public class OwnClient extends JFrame implements ActionListener {
    JTextField servresp;
    Socket s;

    static PrivateKey priv;
    static PublicKey pub;
    static PublicKey pubserv;
    JTextArea clientRequest;
    JButton sendFile, ok;
    JTextField status;
    JTextField encr;
    JButton connect;
    static KeyPair keys;
    public String name;
    static File privateKeyFile = new File("client//private.key");
    static File publicKeyFile = new File("client//public.key");



    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here

        try {

            int serverPort = 3128; // здесь обязательно нужно указать порт к которому привязывается сервер.
            String address = "127.0.0.1"; // это IP-адрес компьютера, где исполняется наша серверная программа.
            generateKey();
            createKeyFiles();
            InetAddress ipAddress = InetAddress.getByName(address);
            Socket socket = new Socket(ipAddress, serverPort);
            OwnClient cli=new OwnClient(socket);
        } catch (IOException e) {
            e.printStackTrace();
        }
         // создаем объект который отображает вышеописанный IP-адрес.


    }
    public OwnClient( Socket s) throws IOException {
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setBounds(975, 345, 400, 400);
        setLayout(new GridLayout(6, 1));

        JPanel buttonPanel = new JPanel();
        JPanel crPanel = new JPanel();
        JPanel yeap = new JPanel();
        JPanel statuspan = new JPanel();
        JPanel servresppan = new JPanel();
        JPanel encrpan = new JPanel();
        status =new JTextField();
        servresp =new JTextField();
        encr =new JTextField();
        encrpan.setLayout(new GridLayout(1,1));
        encrpan.add(encr);
        sendFile = new JButton("send to server");
        //sendFile.setBackground(Color.BLUE);
        //getFile = new JButton("get from server");
        //sendFile.setBackground(Color.CYAN);

        connect = new JButton("connection");
        connect.setBackground(Color.green);
        ok = new JButton("request");
        clientRequest = new JTextArea();

        sendFile.setEnabled(false);
        //getFile.setEnabled(false);
        ok.setEnabled(false);
        encr.setEnabled(false);
        status.setEnabled(false);
        servresp.setEnabled(false);
        clientRequest.setEnabled(false);
        status.setBackground(Color.WHITE);
        clientRequest.setBackground(Color.WHITE);

        connect.addActionListener(this);
        ok.addActionListener(this);

        buttonPanel.setLayout(new GridLayout(1, 4));
        buttonPanel.add(connect);

        crPanel.setLayout(new GridLayout(1, 1));
        crPanel.add(clientRequest);
        statuspan.setLayout(new GridLayout(1,1));
        statuspan.add(status);
        servresppan.setLayout(new GridLayout(1,1));
        servresppan.add(servresp);

        yeap.setLayout(new GridLayout(1,1));
        yeap.add(ok);

        add(buttonPanel);
        add(crPanel);
        add(encrpan);
        add(yeap);
        add(servresppan);
        //add(new JLabel("ВАШЕ МЕСТО ДЛЯ РЕКЛАМЫ"));
        add(statuspan);
        setVisible(true);
        this.s=s;


    }

    public void run() {
        try {

            InputStream sin = s.getInputStream();
            OutputStream sout = s.getOutputStream();
            DataInputStream in = new DataInputStream(sin);
            DataOutputStream out = new DataOutputStream(sout);
            String line;
            ObjectOutputStream obOut = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream obIn = new ObjectInputStream(s.getInputStream());


            obOut.writeObject(pub);
            obOut.flush();
            Object obj = obIn.readObject();
            pubserv = (PublicKey) obj;
            status.setText("Получен открытый ключ: "+pubserv.toString());
            System.out.println("Получен открытый ключ: "+pubserv.toString());
            status.setText("Отправлен открытый ключ: "+pub.toString());
            System.out.println("Отправлен открытый ключ: "+pub.toString());
            line = in.readUTF();

            line = decrypt(line, priv);
            line = encrypt(line, pubserv);
            out.writeUTF(line);
            out.flush();
            line = in.readUTF();
            status.setText("Посылаем имя: " + name);
            System.out.println("Посылаем имя: " + name);
            out.writeUTF(name);
            out.flush();

            int length = in.readInt();
            String strcert = "";
            if (length > 0) {
                byte[] cert = new byte[length];
                in.readFully(cert, 0, cert.length); // read the message
                strcert = getDecB64(cert);
            }
            String dig1 = getDigest(strcert);


            length = in.readInt();
            byte[] sign = null;
            if (length > 0) {
                sign = new byte[length];
                in.readFully(sign, 0, sign.length); // read the message

            }
            if (verifySign(dig1, sign, pubserv)) {
                status.setText("Подписи совпадают");
                System.out.println("Подписи совпадают");
                wr_2_file(strcert + "\n" + byte2Hex(sign), name);
                out.writeUTF("Ok");
                out.flush();
            }

        } catch (Exception e) {
            Logger.getLogger(sertserver.SertServer.class.getName()).log(Level.SEVERE, null, e);
        } // вывод исключений


    }

    static String encrypt(String str, PublicKey pub) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher ecipher;
        ecipher = Cipher.getInstance("RSA");

        ecipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] utf8 = str.getBytes("UTF8");
        byte[] enc = ecipher.doFinal(utf8);
        return new sun.misc.BASE64Encoder().encode(enc);
    }

    static String decrypt(String str, PrivateKey priv) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher dcipher;
        dcipher = Cipher.getInstance("RSA");
        dcipher.init(Cipher.DECRYPT_MODE, priv);
        byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);
        byte[] utf8 = dcipher.doFinal(dec);
        return new String(utf8, "UTF8");
    }

    static void wr_2_file(String s, String path) throws FileNotFoundException, IOException {
        byte[] base64data = getEncB64(s);

        File fcheck = new File("client/" + path + ".crt");
        if (fcheck.exists()) fcheck.delete();

        FileOutputStream fs = new FileOutputStream("client/" + path + ".crt");
        fs.write(base64data, 0, base64data.length);

        fs.close();
    }

    static byte[] getEncB64(String s) {
        return Base64.getEncoder().encode(s.getBytes());
    }

    static public String getDigest(String input) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest d = MessageDigest.getInstance("md2");
        d.reset();
        d.update(input.getBytes());
        return byte2Hex(d.digest());//buf = encrypt(hash,pub);
    }

    static private void createKeyFiles() throws IOException {
        String dir = new File("").getAbsolutePath() + "/client";
        //System.out.println(dir);
        File f;
        f = new File(dir);
        if (!f.isDirectory()) if (!f.mkdir()) JOptionPane.showMessageDialog(null, "Невозможно создать папку");

        if (privateKeyFile.getParentFile() != null) {
            privateKeyFile.getParentFile().mkdirs();
        }
        privateKeyFile.createNewFile();

        if (publicKeyFile.getParentFile() != null) {
            publicKeyFile.getParentFile().mkdirs();
        }
        publicKeyFile.createNewFile();

        BufferedWriter pubOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(publicKeyFile)));
        pubOut.write(byte2Hex(pub.getEncoded()));
        pubOut.flush();
        pubOut.close();


        BufferedWriter privOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(privateKeyFile)));
        privOut.write(byte2Hex(priv.getEncoded()));
        privOut.flush();
        privOut.close();

    }

    public static boolean verifySign(String input, byte[] inputSign, PublicKey pkey) throws Exception {

        Signature signature = Signature.getInstance("MD2withRSA");
        signature.initVerify(pkey);
        signature.update(input.getBytes());
        return signature.verify(inputSign);

    }

    public static String byte2Hex(byte b[]) {
        java.lang.String hs = "";
        java.lang.String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = java.lang.Integer.toHexString(b[n] & 0xff);
            if (stmp.length() == 1) hs = hs + "0" + stmp;
            else hs = hs + stmp;
        }
        return hs.toLowerCase();

    }

    static public void generateKey() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, new SecureRandom());
            keys = keyGen.generateKeyPair();

            pub = keys.getPublic();
            priv = keys.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    static String getDecB64(byte[] base64data) throws UnsupportedEncodingException {
        return new String(Base64.getDecoder().decode(base64data), "UTF-8");
    }

    @Override
    public void actionPerformed(ActionEvent e) {

        String button = e.getActionCommand();

        StringBuilder filename = new StringBuilder();
        StringBuilder filedirectory = new StringBuilder();


        byte[] data; // = new byte[1000];

        switch (button) {
            case "connection": {
                new Authorization(this);

            }
                break;
            case "request":
            {

                String line = clientRequest.getText();
                System.out.println("Незашифрованное сообщение " + line);
                status.setText("Незашифрованное сообщение " + line);
                try {
                    InputStream sin = s.getInputStream();
                    OutputStream sout = s.getOutputStream();
                    DataInputStream in = new DataInputStream(sin);
                    DataOutputStream out = new DataOutputStream(sout);
                    line = encrypt(line, pubserv);
                    encr.setText("Зашифрованное сообщение " + line);
                    out.writeUTF(line);
                    out.flush();
                    line = in.readUTF();
                    servresp.setText("Пришло зашифрованное сообщение : " + line);
                    System.out.println("Пришло зашифрованное сообщение : " + line);
                    line = decrypt(line, priv);
                    status.setText("Расшифрованное сообщение : " + line);
                    System.out.println("Расшифрованное сообщение : " + line);
                    System.out.println();
                } catch (IOException e1) {
                    e1.printStackTrace();
                } catch (NoSuchAlgorithmException e1) {
                    e1.printStackTrace();
                } catch (InvalidKeyException e1) {
                    e1.printStackTrace();
                } catch (NoSuchPaddingException e1) {
                    e1.printStackTrace();
                } catch (BadPaddingException e1) {
                    e1.printStackTrace();
                } catch (IllegalBlockSizeException e1) {
                    e1.printStackTrace();
                }
                clientRequest.selectAll();
                clientRequest.replaceSelection("");

            }

        }

    }
}