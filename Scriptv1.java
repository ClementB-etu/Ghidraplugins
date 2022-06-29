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
//Ghidra Script - Inspecting data (strings) and returning a possible decoding function
//@category    Examples
//@keybinding  ctrl shift COMMA
//@toolbar    world.png


import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangTokenGroup;

import ghidra.util.Msg;

import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.string.*;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.Address;

import java.lang.Math;
import java.util.*;
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;

public class Scriptv1 extends GhidraScript {
    

    /*
    * Name of the file created to store the decompiled "decoding function"
    */
    String resfilename = "res.c";


    @Override
    protected void run() throws Exception {
        /*
        *
        */
        Memory mem = currentProgram.getMemory();
        MemoryBlock[] memblocksSections = mem.getBlocks();

        /*
        *
        */
        Set<FoundString> list = new HashSet<FoundString>();
        FoundStringCallback foundStringCallback = foundString -> list.add(foundString);
        StringSearcher ss = new StringSearcher(currentProgram, 5, 1, false, true);
        AddressSetView addressview = ss.search(null,foundStringCallback, true, monitor);

        /*
        *   
        */
        Map<Address, Integer> refcount = new HashMap<Address, Integer>();
        Map<Address, List<String>> refobj = new HashMap<Address, List<String>>();

        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                byte[] b = new byte[(int)secblock.getSize()];                
                Address addr = secblock.getStart();

                //Iterates through .rodata to "create" str (even big strings that aren't analyzed by Ghidra's analyzer)
                while (secblock.contains(addr))
                {
                    Data dat = currentProgram.getListing().getDataAt(addr);
                    long lgth = dat.getLength();

                    /*
                    * Initially, "unrecognized" strings are 1byte-long while they aren't identified yet as proper string, but as a long sequence of byte
                    */
                    if (lgth == 1)
                    {
                        try 
                        {
                            currentProgram.getListing().createData​(addr, StringDataType.dataType);
                            //Datatype changed, so string has been created and dat (value, length ... )has changed

                            dat = currentProgram.getListing().getDataAt(addr);
                            lgth = dat.getLength();
                            //If lgth doesn't change, it isn't a string so codeunit needs to be clear in order not to crash during the next execution (if string exist at this addr, it crashes when creating string)
                            if (lgth == 1) 
                            {
                                currentProgram.getListing().clearCodeUnits(addr, addr.add(1), true);
                            }
                            addr = addr.add(lgth);

                        } catch (Exception e) {
                            println(e.getMessage());
                        }

                    } else {
                        addr = addr.add(lgth);
                    }  
                }
                break;
            }
        }

        for (FoundString f : list)
        {   
            Data data = getDataAt(f.getAddress());
            try
            {
                ReferenceIterator refit = data.getReferenceIteratorTo();

                refit.forEach(ref -> {
                    Address addrFrom = ref.getFromAddress();
                    Instruction i = getInstructionAt(addrFrom);

                    if (i.getMnemonicString().equals("PUSH"))
                    {
                        Instruction nextinstr = i.getNext();
                    
                        while (!nextinstr.getMnemonicString().equals("CALL"))
                        {
                            nextinstr = i.getNext();  
                        }
                        //Retrieve address "used" by the CALL instruction
                        Address[] flows = nextinstr.getFlows();
                        for (int j = 0; j<flows.length;j++)
                        {
                            println("ref : " + ref + " -> " + flows[j]); 
                            if (refcount.containsKey(flows[j]))
                            {
                                refcount.put(flows[j],refcount.get(flows[j]) + 1);

                                List<String> listStr = new ArrayList<String>();
                                listStr.addAll(refobj.get(flows[j]));
                                listStr.add(f.getDataInstance​(mem).toString());
                                refobj.put(flows[j],listStr);
                            } else {
                                refcount.put(flows[j],1);

                                List<String> listStr = new ArrayList<String>();
                                listStr.add(f.getDataInstance​(mem).toString());
                                refobj.put(flows[j],listStr);
                            }
                        }    
                    } 
                });

            } catch (Exception e) { }                                 
        }

        int max = Collections.max(refcount.values());
        Address addrsus = null;
        Function fct = null;
        
        for (Map.Entry<Address, Integer> entry : refcount.entrySet()) 
        {
            if (entry.getValue() == max)
            {
                addrsus = entry.getKey();
                fct = getFunctionAt(addrsus);
                println("Suspicious address : " + (addrsus) + " ( "  + fct.getName() + " called with a string " + max + " times ) :");                
            }
        }

        List<String> res = refobj.get(addrsus);  
        res.forEach(r -> println(" * " + r));


        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        DecompileResults ressubstr = ifc.decompileFunction(fct,0,monitor);
        ClangTokenGroup tokgroupsubstr = ressubstr.getCCodeMarkup();
        String ccode = tokgroupsubstr.toString();

        try
        {
            String path = resfilename;
            File code = new File(path);
            FileWriter fw = new FileWriter(code, false);
            PrintWriter pw = new PrintWriter(fw);
            pw.println(ccode);
            pw.close();
            println(" ** Code of the suposed decoding function on file : ~/" + path);
        } catch (Exception e) { 
            println("[ERROR] " + e.getMessage());
        }
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