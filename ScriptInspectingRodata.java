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
//Ghidra Script - Sanitizing & Inspecting sanitized data in .rodata
//@category    Examples
//@keybinding  ctrl shift COMMA
//@toolbar    world.png

import ghidra.app.script.GhidraScript;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.symbol.ReferenceIterator;

import ghidra.program.util.DefinedDataIterator;
import ghidra.app.util.XReferenceUtil;


import ghidra.util.Msg;
import java.lang.Math;
import java.util.*;  
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.Charset;


public class ScriptInspectingRodata extends GhidraScript {

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
        ByteProvider byteProvider = new MemoryByteProvider(mem, currentProgram.getImageBase());
        MemoryBlock[] memblocksSections = mem.getBlocks();



        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                byte[] b = new byte[(int)secblock.getSize()];
                if (secblock.getBytes(secblock.getStart(),b) > -1)
                {
                    println("[ "+ secblock.getName() +" ] : bytes retreived");
                }
                
                Address addr = secblock.getStart();

                //Iterates through rodata to sanitize str (even with big strings that aren't analyzed by Ghidra's analyzer)
                while (secblock.contains(addr))
                {
                    Data dat = currentProgram.getListing().getDataAt(addr);
                    long lgth = dat.getLength();

                    if (lgth == 1)
                    {
                        try 
                        {
                            currentProgram.getListing().createData​(addr, StringDataType.dataType);
                            //Datatype changed, so string has been created and dat (value, length ... )has changed

                            dat = currentProgram.getListing().getDataAt(addr);
                            lgth = dat.getLength();
                            //If lgth doesn't change, it isn't a string so codeunit need to be clear in order not to crash during the next execution (if string exist at this addr, crash when creating string)
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

                        //println("dat : " + ((String) dat.getValue()) + "(number or letter ? : " + getNumberOrLetter(((String) dat.getValue())) + " )");
                        //println("dat : " + ((String) dat.getValue()) + "(appropriate length ? : " + getAppropriateLength(((String) dat.getValue())) + " )");
                        //println("dat : " + ((String) dat.getValue()) + "(entropy : " + getShannonEntropy(((String) dat.getValue())) + " )");
                        println("dat : " + ((String) dat.getValue()) + "(nbr XREF : " + nbref + " )");
                    }
                }
                                
                    
            } else {
                //println("Section : " + secblock.getName());        
            }
        }
    }

    public static byte[] getSliceOfArray(byte[] arr, int start, int end)
    {
  
        // Get the slice of the Array
        byte[] slice = new byte[end - start];
  
        // Copy elements of arr to slice
        for (int i = 0; i < slice.length; i++) {
            slice[i] = arr[start + i];
        }
  
        // return the slice
        return slice;
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

    //Return 1 if s contient seulement [0-9] et [aA-zZ], 0 sinon
    public int getNumberOrLetter(String s) {
		if (s == null) {
			return 0;
		}
		for (int c_ = 0; c_ < s.length(); ++c_) {
			char cx = s.charAt(c_);
            int ascii = (int) cx;

            if (!(ascii>47 && ascii<58) && !(ascii>64 && ascii<91) && !(ascii>96 && ascii<123))
            {
                return 0;
            }
		}
	
		return 1;
	}

    //Return 1 if s est d'une longueur multiple de 4 (car chaque caractère encode utilise 2bytes(4 caractères))
    public int getAppropriateLength(String s) {
		if (s == null) {
			return 0;
		}

		if ((s.length()%4) == 0)
        {
		    return 1;
        } else {
            return 0;
        }
	
	}
}