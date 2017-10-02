/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sertserver;

import java.math.BigInteger;
import java.util.Random;


public class OwnCert {
    
    BigInteger serNum;
    String signAlg;
    String issuer;
    String InvalidDateBefore;
    String InvalidDateAfter;
    String subj;
    String openKey;
    String sign;
    
    public OwnCert(){
        serNum = new BigInteger(128,new Random());  
    }
    
    public void setSingAlg(String s){ 
        signAlg = s;
    }
    
    public void setIssuer(String s){
        issuer = s;
    }
    
    public void setDateBefore(String s){
        InvalidDateBefore = s;
    }
    
    public void setDateAfter(String s){
        InvalidDateAfter = s;
    }
    
    public void setSubj(String s){
        subj = s; 
    }
    
    public void setOkey(String s){
        openKey = s;    
    }
    
    public void setSign(String s){
        sign = s;
          
    }
    
    public String  recieveAll(){
        String s = 
                "Имя/адрес сервера: "+issuer+"\n"+
                "Заданное имя/адрес (клиента): "+subj+"\n"+
                "Серийный номер: "+serNum.toString()+"\n"+
                "Тип цифровой подписи: "+signAlg+"\n"+
                
//                +InvalidDateBefore+"\n"
//                +InvalidDateAfter+"\n"
                
                "Открытый ключ: "+openKey;
        return s;
    }
}
