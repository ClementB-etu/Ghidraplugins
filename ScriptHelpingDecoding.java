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

//Ghidra Script - Inspecting data (strings) and returning a possible decoding function (`resfilename`.c)
//@category    Examples
//@author Clément BELLEIL

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


public class ScriptHelpingDecoding extends GhidraScript {
    
    /*
    * Name of the file created with the decompiled "decoding function"
    */
    String resfilename = "res.c";

    /** Implemented method from `GhidraScript` used when the plugin is launched 
    * @return void
    */
    @Override
    protected void run() throws Exception {

        /*
        * Memory object to collect data (bytes)
        */
        Memory mem = currentProgram.getMemory();
        MemoryBlock[] memblocksSections = mem.getBlocks();

        /*
        * refcount : (Address, amount of times that address is called with a string as parameter), the address with the maximum integer will be guessed as the decoding function
        * refobj : (Address, list of strings that are used as parameter by the function at the address), this list is displayed at the end of the analysis to show how encoded strings look like
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
        
        /*
        * This part is useful to be sure that all strings are identified as such by the Ghidra Analyzer
        * Without it, some encoded string might be missing at the end
        */
        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                //b contains .rodata bytes
                byte[] b = new byte[(int)secblock.getSize()];                
                Address addr = secblock.getStart();

                //Iterates through .rodata by incrementing the value of addr to "create" str (big strings that aren't analyzed by Ghidra's analyzer)
                while (secblock.contains(addr))
                {
                    Data dat = currentProgram.getListing().getDataAt(addr);
                    long lgth = dat.getLength();

                    //Initially, "unrecognized" strings are 1byte-long while they aren't identified yet as proper string
                    if (lgth == 1)
                    {
                        try 
                        {
                            //This line converts long sequence of byte to string if it is
                            currentProgram.getListing().createData​(addr, StringDataType.dataType);

                            //Datatype changed, so string has been created and dat (value, length ... ) changed too
                            dat = currentProgram.getListing().getDataAt(addr);
                            lgth = dat.getLength();

                            //If lgth hasn't changed, `dat` isn't a string, so codeunit needs to be cleared for the program not to crash during the next execution
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
            }
        }

        /*
        * list : list used to deal with all strings in the executable
        * ss : StringSearcher object implemented in the `ghidra.program.util.string` package
        * foundStringCallback : callback function called when a string is found by ss
        */
        Set<FoundString> list = new HashSet<FoundString>();
        FoundStringCallback foundStringCallback = foundString -> list.add(foundString);
        StringSearcher ss = new StringSearcher(currentProgram, 5, 1, false, true);
        ss.search(null,foundStringCallback, true, monitor);


        for (FoundString f : list)
        {   

            Data data = getDataAt(f.getAddress());
            try
            {
                ReferenceIterator refit = data.getReferenceIteratorTo();
                /*
                * A reference is a couple (AddressFrom,AddressTo) 
                * For each reference that has the string's address as AddressTo
                * We look for the instruction at the AddressFrom
                * If this instruction's mnemonic is a 'PUSH', the string is likely to be used as a parameter by a function
                * So we look for the next CALL instruction 
                * And we store the address of the called function
                */
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

                        /*
                        * For each flow (i.e an address used by the 'CALL' instruction)
                        * We store it in a map (Map<Address, String> `refcount`) with a '1' as value if the address wasn't already in it
                        * Otherwise, we increment the value
                        *
                        * There is also an other map (Map<Address, List<String>> `refobj`) which stores the address of the function called 
                        * and the list of strings used as parameter (if called various time)
                        */
                        Address[] flows = nextinstr.getFlows();
                        for (int j = 0; j<flows.length;j++)
                        {
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

            } catch (Exception e) {
                println(e.getMessage());
            }                                 
        }

        /*
        * By doing so, the supposed decoding function is the function that has the bigger value in `refcount`
        * So we retrieve the name, and the decompiled .c code for the user to look through the code
        */
        int max = Collections.max(refcount.values());
        Address addrsus = null;
        Function fct = null;
        
        for (Map.Entry<Address, Integer> entry : refcount.entrySet()) 
        {
            if (entry.getValue() == max)
            {
                addrsus = entry.getKey();
                fct = getFunctionAt(addrsus);
                println("Suspicious address : " + (addrsus));                
                println("Suspicious function : "  + fct.getSignature() + " || called with a string " + max + " times");          
            }
        }

        /*
        * Strings used by the supposed decoding function are printed
        */
        List<String> res = refobj.get(addrsus);  
        res.forEach(r -> println(" * " + r));
        
        /*
        * The decompiled code of the supposed decoding function provided by ghidra is written in a .c file
        * For the user to investigate on how the decoding process works
        */
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        DecompileResults rescode = ifc.decompileFunction(fct,0,monitor);
        ClangTokenGroup tokgroupcode = rescode.getCCodeMarkup();
        String ccode = tokgroupcode.toString();

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
    
}