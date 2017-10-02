package client;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class Authorization extends JFrame implements ActionListener {

    private JTextField loginField;
    OwnClient client;

    public Authorization(OwnClient client) {
        super("Авторизация");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setBounds(1080, 215, 400, 100);
        this.client = client;
// Настраиваем первую горизонтальную панель (для ввода логина)
        Box box1 = Box.createHorizontalBox();
        JLabel loginLabel = new JLabel("Введите имя:");
        loginField = new JTextField(15);
        box1.add(loginLabel);
        box1.add(Box.createHorizontalStrut(6));
        box1.add(loginField);
// Настраиваем третью горизонтальную панель (с кнопками)
        Box box3 = Box.createHorizontalBox();
        JButton ok = new JButton("Ввод");
        ok.addActionListener(this);
        JButton cancel = new JButton("Отмена");
        cancel.addActionListener(this);
        box3.add(Box.createHorizontalGlue());
        box3.add(ok);
        box3.add(Box.createHorizontalStrut(12));
        box3.add(cancel);
// Размещаем три горизонтальные панели на одной вертикальной
        Box mainBox = Box.createVerticalBox();
        mainBox.setBorder(new EmptyBorder(0, 0, 0, 0));
        mainBox.add(box1);
        mainBox.add(Box.createVerticalStrut(17));
        mainBox.add(box3);
        setContentPane(mainBox);
        pack();
        setResizable(false);
        setVisible(true);
    }

    public static void main(String[] args) {

    }

    @Override
    public void actionPerformed(ActionEvent e) {

        String action = e.getActionCommand();
        if (action.equals("Ввод")) {

            client.name=loginField.getText();
            dispose();
            setVisible(false);
            System.out.println("Answer: "+client.name);
            client.sendFile.setEnabled(true);
            client.ok.setEnabled(true);
            client.clientRequest.setEnabled(true);
            client.connect.setEnabled(false);
            client.run();
        } else if (action.equals("Отмена")) {
            dispose();
            setVisible(false);
        }

    }


}

