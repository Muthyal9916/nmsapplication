package com.example.demo;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

import javax.servlet.http.HttpServletResponse;

import org.nmap4j.Nmap4j;
import org.nmap4j.core.nmap.ExecutionResults;
import org.nmap4j.data.NMapRun;
import org.nmap4j.data.nmaprun.Host;
import org.nmap4j.parser.OnePassParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class NmapController {

	@RequestMapping(value="/{ipaddress}/{udportcp}",method=RequestMethod.GET)
	public void getNmaPDetails(HttpServletResponse response,@PathVariable("ipaddress") String paramName,@PathVariable("udportcp") String optionVal) throws IOException {
		
		ArrayList<String> ipaddresList = new ArrayList<String>();
		
		PrintWriter out = response.getWriter();
		String originalvalue = paramName.replaceAll("_","/");
		
		 Nmap4j nmap4j = new Nmap4j("/usr") ;
	   	 nmap4j.includeHosts(originalvalue) ;
	   	 if(optionVal.equalsIgnoreCase("udp"))
	   	 {
	 	nmap4j.addFlags("--privileged -sU -p161");
	   	 }
	   	 else
	   	 {
	   		nmap4j.addFlags("--privileged -sT -p2022");
	   	 }

	   	  try{
	   	  nmap4j.execute() ; 
	   	 }catch(Exception e){
	   		 e.printStackTrace();
	   	  System.out.println("error execute");

	   	 }
	   	 if( !nmap4j.hasError() ) { 

		   		ExecutionResults res=nmap4j.getExecutionResults();
		   		String nmapRun = nmap4j.getOutput() ;
		   	   	
		   	   	OnePassParser opp = new OnePassParser() ;
		   	   	NMapRun nmapRun1 = opp.parse( nmapRun, OnePassParser.STRING_INPUT ) ;
		   	   	ArrayList<Host> hosts=nmapRun1.getHosts(); 
		   	   	for(Host ipAddr:hosts) {
		   	   	if(ipAddr.getPorts().getPorts().get(0).getState().getState().equalsIgnoreCase("open")) {
		   	   		ipaddresList.add(ipAddr.getAddresses().get(0).getAddr());
		   	   		
		   		}
		   	   		}
		   	   	
		   	  System.out.println(""+res.getOutput()+"\n");
		   	 }
	   	  else {
	   	   System.out.println( nmap4j.getExecutionResults().getErrors() ) ; 
	   	   }
	   	 

		 System.out.println("ipaddresList"+ipaddresList);
	 	 out.println(ipaddresList);
	 
	 	
	}
}
