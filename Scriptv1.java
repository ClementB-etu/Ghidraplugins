/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Ghidra Script - Inspecting data (strings) and looking for a possible decoding function
//@category    Examples
//@keybinding  ctrl shift COMMA
//@toolbar    world.png


import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangTokenGroup;

import ghidra.util.Msg;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.util.string.*;
import ghidra.program.model.address.AddressSetView;

import java.lang.Math;
import java.util.*;
import java.util.stream.*;  
import java.util.zip.*;
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;

public class Scriptv1 extends GhidraScript {
    

    /*
    * Name of the file created to be compiled and used to decode suspicious strings
    */
    String decodefilename = "decode.c";
    String resfilename = "res.txt";
    Set<String> foundstr = new HashSet<String>(); 


    @Override
    protected void run() throws Exception {

        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

       
        Listing listing = currentProgram.getListing();
        InstructionIterator listIt = listing.getInstructions(true);
        Memory mem = currentProgram.getMemory();


        Set<FoundString> list = new HashSet<FoundString>();

        FoundStringCallback foundStringCallback = foundString -> list.add(foundString);

        StringSearcher ss = new StringSearcher(currentProgram, 5, 1, false, true);
        
        AddressSetView addressview = ss.search(null,foundStringCallback, true, monitor);

        for (FoundString f : list)
        {   
            ReferenceIterator refit = f.getDataInstance​(mem).getReferenceIteratorTo();

            println(">" + f.getDataInstance​(mem));                    
        }


        /*for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                

                double meanScore = 0;
                Map<String, Data> data = new HashMap<String, Data>();
                Map<String, Double> scores = new HashMap<String, Double>();
                Set<String> suspiciousstr = new HashSet<String>();
                Map<Address, Integer> flowcount = new HashMap<Address, Integer>();

                //At this point, all the potentially encoded strings are in 'Defined String' table, so we iterate through it
                for (Data dat : DefinedDataIterator.definedStrings(currentProgram) ) {
                    Address strAddr = dat.getMinAddress();
                    if ((secblock.contains(strAddr)) && (dat.getLength()>5))
                    {                        
                        int nbref = 0;
                        ReferenceIterator refit = dat.getReferenceIteratorTo();
                        while(refit.hasNext())
                        {
                            nbref++;
                            refit.next();
                        }

                        String str = (String) dat.getValue();
                        double entr = getShannonEntropy(str);
                        meanScore += entr;

                        println("\n\nSTR entropy : " + entr + " ( " + str + " )");

                        data.put(str, dat);
                        scores.put(str,entr);
                        
                    }
                }
                
                meanScore /= scores.size();
                println("mean entropy is : " + (meanScore));

                
                //Now, we calculate the mean and the standard deviation
                
                double etypeScore = 0;
                double treshold = 0;
                int nbdetect = 0;
                for (Map.Entry<String, Double> entry : scores.entrySet()) {
                    etypeScore += Math.pow((entry.getValue()-meanScore),2);
                }

                etypeScore = Math.sqrt(etypeScore / scores.size());
                println("standard deviation entropy is : " + etypeScore);

                for (String s : suspiciousstr) {
                    
                    ReferenceIterator refit = data.get(s).getReferenceIteratorTo();
                    while(refit.hasNext())
                    {   
                        Address addrtmp = refit.next().getFromAddress();
                        Instruction i = getInstructionAt(addrtmp);
                        try
                        {
                            if (i.getMnemonicString().equals("PUSH"))
                            {
                                Instruction nextinstr = i.getNext();
                            
                                if (nextinstr.getMnemonicString().equals("CALL"))
                                {
                                    //Retrieve address used by the CALL instruction
                                    Address[] flows = nextinstr.getFlows();
                                    for (int j = 0; j<flows.length;j++)
                                    {
                                        if (flowcount.containsKey(flows[j]))
                                        {
                                            flowcount.put(flows[j],flowcount.get(flows[j]) + 1);
                                        } else {
                                            flowcount.put(flows[j],1);
                                        }
                                    }
                                    
                                }
                            }   
                        } catch (Exception e) { }
                    }
                }
                
                try
                {
                    int max = Collections.max(flowcount.values());

                    for (Map.Entry<Address, Integer> entry : flowcount.entrySet()) 
                    {
                        if (entry.getValue() == max)
                        {
                            //analyseAddress(entry.getKey());
                        }
                    }
                } catch (Exception e) { }
                 
                ProcessBuilder pb = new ProcessBuilder("gcc", "-m32",decodefilename,"-o","decode");
                pb.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/"));   
                Process procgcc = pb.start();
                procgcc.waitFor();


                try
                {
                    String pathres = "/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/" + resfilename;
                    File resfile = new File(pathres);
                    FileWriter fwres = new FileWriter(resfile, false);
                    PrintWriter pwres = new PrintWriter(fwres);
                    
                    for (String s : suspiciousstr) {

                    ProcessBuilder pbdecode = new ProcessBuilder("./decode", s);
                    pbdecode.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/"));   
                    Process procdecode = pbdecode.start();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(procdecode.getInputStream()));
                    Stream<String> line = reader.lines();
                    String res = String.join("\n",line.collect(Collectors.toList()));

                    pwres.println(res);
                    procdecode.waitFor();                
                    }

                    pwres.close();

                } catch (Exception e) { 
                    println("[ERROR] " + e.getMessage());
                }

                
            }
        }*/
    }

    public int analyseAddress(Address addr)
    {
        Function fct = getFunctionAt(addr);
        //println("~ " + fct.getName()  + "  ~");
        Set<Function> fctcalled = fct.getCalledFunctions(monitor);
        Function fctsubstr = null;

        for (Function f : fctcalled)
        {
            if (!(f.getName().startsWith("FUN")) && !(f.getName().startsWith("_"))) {
                //println("~ " + f.getName() + " ~");
                fctsubstr = f;
                break;
            }
        }
        
        try
        {
            Parameter p = fct.getParameters()[0];
            p.setDataType(new PointerDataType(new CharDataType()),true,true,fct.getSignatureSource());

            for (Variable v : fct.getLocalVariables())
            {
                if (v.getDataType().isEquivalent(new Undefined1DataType()))
                {
                    v.setDataType(new ArrayDataType(new CharDataType(),4,1),fct.getSignatureSource());
                }
            }
            fctsubstr.setReturnType(new PointerDataType(new CharDataType()),fctsubstr.getSignatureSource());
        } catch (Exception e){ }


        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        DecompileResults ressubstr = ifc.decompileFunction(fctsubstr,0,monitor);
        ClangTokenGroup tokgroupsubstr = ressubstr.getCCodeMarkup();
        String ccodesubstr = tokgroupsubstr.toString();

        DecompileResults resdecode = ifc.decompileFunction(fct,0,monitor);
        ClangTokenGroup tokgroupdecode = resdecode.getCCodeMarkup();       
        String ccode = tokgroupdecode.toString();

        try
        {
            String path = "/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/" + decodefilename;
            File code = new File(path);
            FileWriter fw = new FileWriter(code, false);
            PrintWriter pw = new PrintWriter(fw);
            pw.println(ccode);
            pw.close();
        } catch (Exception e) { 
            println("[ERROR] " + e.getMessage());
        }
       
        return 0;
    }

    public static double log2(double x) {
		return (double) (Math.log(x) / Math.log(2));
	}

	public double getShannonEntropy(String s) {
		if (s == null) {
			return 0.0;
		}
		int n = 0;
		Map<Character, Integer> occ = new HashMap<>();
		for (int c_ = 0; c_ < s.length(); ++c_) {
			char cx = s.charAt(c_);
			if (occ.containsKey(cx)) {
				occ.put(cx, occ.get(cx) + 1);
			} else {
				occ.put(cx, 1);
			}
			++n;
		}
		double e = 0.0;
		for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
			char cx = entry.getKey();
			double p = (double) entry.getValue() / n;
			e += p * log2(p);
		}
		return -e;
	}

   
}