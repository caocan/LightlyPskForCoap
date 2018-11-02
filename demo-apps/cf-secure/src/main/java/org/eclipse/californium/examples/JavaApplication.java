package org.eclipse.californium.examples;

import javax.swing.*;
import java.awt.*;

class JavaApplication extends JFrame {
    public JavaApplication()
    {

        setTitle("运行数据");

        setSize(700, 300);

        setLocation(300, 300);

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        setVisible(true);
    }

    public static void MyDialog(String Algorithm, int times, int DatagramPackages, long during)
    {
        JavaApplication application = new JavaApplication();

        application.setBackground(Color.WHITE);

        //初始化一个容器
        Container container = application.getContentPane();

        //初始化一个panel
        JPanel panel = new JPanel();

        Font font = new Font("Serif",1,20);

        JTextArea textarea = new JTextArea("执行算法：" + Algorithm + "\n运行次数 = " + times + "\n数据报个数 = " +
                DatagramPackages + "\n耗时 = " + during + "ms", 30, 30 );

        textarea.setFont(font);

        textarea.setForeground(Color.RED);

        textarea.setBackground(Color.BLACK);

        panel.add(textarea);

        container.add(panel);

        application.setVisible(true);
    }
}
