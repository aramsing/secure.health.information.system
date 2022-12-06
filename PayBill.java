/*
Name: Arjun Ramsinghani
Title: Secure Health Information System
Course: CS 4331-001 -- Software Security
 */

package secure.health.information.system;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author arams
 */
public class PayBill extends javax.swing.JFrame {
    
    String key = "12345678"; // key for encription
    /**
     * Creates new form PayBill
     */
    public PayBill() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     * https://www.youtube.com/watch?v=LP7_DlIe670&list=PLFDH5bKmoNqxtOTzA4tjo-Exck6T2v7cG&index=25
     * https://www.youtube.com/watch?v=dsYKi0LzGX8
     */
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        displaybutton = new javax.swing.JButton();
        processbutton = new javax.swing.JButton();
        paybutton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        paymenttable = new javax.swing.JTable();
        jScrollPane2 = new javax.swing.JScrollPane();
        processingtable = new javax.swing.JTable();
        cancelbutton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Bills");

        displaybutton.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        displaybutton.setText("Display");
        displaybutton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                displaybuttonActionPerformed(evt);
            }
        });

        processbutton.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        processbutton.setText("Process");
        processbutton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                processbuttonActionPerformed(evt);
            }
        });

        paybutton.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        paybutton.setText("Pay");
        paybutton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                paybuttonActionPerformed(evt);
            }
        });

        paymenttable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Date", "Visit Type", "Amount", "Paid"
            }
        ));
        jScrollPane1.setViewportView(paymenttable);

        processingtable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Date", "VisitType", "Amount", "Title "
            }
        ));
        jScrollPane2.setViewportView(processingtable);

        cancelbutton.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        cancelbutton.setText("Cancel");
        cancelbutton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelbuttonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(displaybutton, javax.swing.GroupLayout.PREFERRED_SIZE, 301, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(462, 462, 462)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 257, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(cancelbutton, javax.swing.GroupLayout.PREFERRED_SIZE, 290, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 900, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(processbutton, javax.swing.GroupLayout.PREFERRED_SIZE, 290, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 920, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(paybutton, javax.swing.GroupLayout.PREFERRED_SIZE, 290, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(51, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(143, 143, 143)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(displaybutton, javax.swing.GroupLayout.PREFERRED_SIZE, 92, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(cancelbutton, javax.swing.GroupLayout.PREFERRED_SIZE, 92, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 683, Short.MAX_VALUE)
                    .addComponent(jScrollPane2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(paybutton, javax.swing.GroupLayout.PREFERRED_SIZE, 92, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(processbutton, javax.swing.GroupLayout.PREFERRED_SIZE, 92, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void displaybuttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_displaybuttonActionPerformed
        // TODO add your handling code here:
        String filepath1 = "paybill.txt"; // get the bills
        File file1 = new File(filepath1);
        String filepath2 = "paybillencrypted.txt"; // file for encryption
        File file2 = new File(filepath2);

        try {
            FileInputStream is1 = new FileInputStream(file1); // take the bill file
            FileOutputStream os1 = new FileOutputStream(file2); // take the encrypted file
            
            FileReader fr = new FileReader(file1); // read regular file
            BufferedReader br = new BufferedReader(fr);

            DefaultTableModel model = (DefaultTableModel) paymenttable.getModel(); // get the table
            Object[] lines = br.lines().toArray(); // read the file into an object array

            for (int i = 1; i < lines.length; i++) {
                String[] row = lines[i].toString().split(","); // split the columns by row
                model.addRow(row); // add the row
            }
            
            DataEncryptionStandard.encrypt(key, is1, os1); // encrypted
        }
        
        catch (FileNotFoundException ex) {
            Logger.getLogger(PayBill.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        catch (Exception ex) {
            Logger.getLogger(PayBill.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_displaybuttonActionPerformed

    private void processbuttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_processbuttonActionPerformed
        // TODO add your handling code here:
        DefaultTableModel model1 = (DefaultTableModel) paymenttable.getModel(); // get first table
        int index[] = paymenttable.getSelectedRows(); // get the rows from first table
        DefaultTableModel model2 = (DefaultTableModel) processingtable.getModel(); // get second table
        paymenttable.selectAll();

        Object[] row = new Object[4];
        for (int i = 0; i < index.length; i++) {
            row[0] = paymenttable.getValueAt(index[i], 0); // get the value at a certain row column
            row[1] = paymenttable.getValueAt(index[i], 1); // get the value at a certain row column
            row[2] = paymenttable.getValueAt(index[i], 2); // get the value at a certain row column
            row[3] = "Processing"; // make new row
            model2.addRow(row); // add row
        }
    }//GEN-LAST:event_processbuttonActionPerformed

    public int bankAuthorize(String crednum) {
        String comp;
        String filepath = "creditcardnumber.txt"; // get the file
        File file = new File(filepath);
        try {
            Scanner myReader = new Scanner(file); // read the file
            while (myReader.hasNextLine()) {
                comp = myReader.nextLine();
                String[] row = comp.split(","); // split the column
                if (row[0].equals(crednum)) {
                    return 1; // 1 is approved
                }
            }
            myReader.close(); // close the file
        }
        
        catch (FileNotFoundException e) {
            System.out.println("An error occurred."); // error statement to console
            e.printStackTrace();
        }
        
        return 0; // not authorized
    }

    private void paybuttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_paybuttonActionPerformed
        // TODO add your handling code here:
        DefaultTableModel model1 = (DefaultTableModel) processingtable.getModel();
        int index[] = processingtable.getSelectedRows();
        DefaultTableModel model2 = (DefaultTableModel) processingtable.getModel();
        
        // get the files
        String filepath1 = "paidbill.txt";
        String filepath2 = "paidbillencrypted.txt";
        String filepath3 = "creditcardnumber.txt";
        String filepath4 = "creditcardnumberencrypted.txt";
        File file1 = new File(filepath1);
        File file2 = new File(filepath2);
        File file3 = new File(filepath3);
        File file4 = new File(filepath4);
        
        try {
            FileInputStream is = new FileInputStream(file3); // get the regular file
            FileOutputStream os = new FileOutputStream(file4); // get the encrypted file
            
            FileReader fr = new FileReader(file3); // read the file
            BufferedReader br = new BufferedReader(fr);
            
            String comparecreditcardnumber;
            comparecreditcardnumber = JOptionPane.showInputDialog("Please enter your credit card number: "); // ask the user to write credit card number

            if (bankAuthorize(comparecreditcardnumber) == 1) { // if the number is correct
                Object[] row = new Object[4];
                for (int i = 0; i < index.length; i++) {
                    row[0] = processingtable.getValueAt(index[i], 0); // get the value at a certain row column
                    row[1] = processingtable.getValueAt(index[i], 1); // get the value at a certain row column
                    row[2] = processingtable.getValueAt(index[i], 2); // get the value at a certain row column
                    row[3] = "Paid"; // make new row
                    model2.addRow(row); // add row
                }

                try {
                    FileInputStream is1 = new FileInputStream(file1); // regular file
                    FileOutputStream os1 = new FileOutputStream(file2); // encrypted file
                    
                    FileWriter fw = new FileWriter(file1, true); // write true for append
                    BufferedWriter bw = new BufferedWriter(fw);

                    for (int i = 0; i < index.length; i++) {
                        model1.removeRow(index[i]);
                        row[0] = processingtable.getValueAt(index[i], 0); // get the value at a certain row column
                        row[1] = processingtable.getValueAt(index[i], 1); // get the value at a certain row column
                        row[2] = processingtable.getValueAt(index[i], 2); // get the value at a certain row column
                        row[3] = "Paid"; // make new row
                        model2.addRow(row); // add row
                        bw.write(row[0] + "," + row[1] + "," + row[2] + "," + row[3]); // write row into file
                        bw.newLine(); // write a new line
                    }
                    
                    DataEncryptionStandard.encrypt(key, is1, os1); // encrypt function
                    
                    JOptionPane.showConfirmDialog(this, "Your payment is confirmed"); // confirmation message
                    
                    bw.close();
                    fw.close(); // close file
                }
                
                catch (IOException ex) {
                    Logger.getLogger(PayBill.class.getName()).log(Level.SEVERE, null, ex);
                }
                
                dispose();
                new SubmitBill().setVisible(true);
            }
            
            else {
                JOptionPane.showMessageDialog(this, "This is not the correct credit card number please try again"); // error message
                dispose();
                new PayBill().setVisible(true);
            }
            
            DataEncryptionStandard.encrypt(key, is, os); // encrypt function
        }
        
        catch (IOException ex) {
            Logger.getLogger(PayBill.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        catch (Exception ex) {
            Logger.getLogger(PayBill.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_paybuttonActionPerformed

    private void cancelbuttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelbuttonActionPerformed
        // TODO add your handling code here:
        dispose();
        new MainWindow().setVisible(true); // back to main
    }//GEN-LAST:event_cancelbuttonActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(PayBill.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(PayBill.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(PayBill.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(PayBill.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new PayBill().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelbutton;
    private javax.swing.JButton displaybutton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton paybutton;
    private javax.swing.JTable paymenttable;
    private javax.swing.JButton processbutton;
    private javax.swing.JTable processingtable;
    // End of variables declaration//GEN-END:variables
}