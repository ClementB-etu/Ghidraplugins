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
//Ghidra Script v1 - redundancy research
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
import ghidra.program.model.mem.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.*;

import ghidra.util.Msg;
import java.lang.Math;
import java.util.*;  
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.Charset;

/*
 * TODO
 * Traiter la dernière instruction ? (pas de next donc pas de taille)
 * Traiter une seule fois les instructions (si déjà dans la map = déjà traité)
 * Converir String en Instruction 
 * Traitement de arrOfInfos
 *
*/

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


        /*
        while (symit.hasNext())
        {   
            Symbol sym = symit.next();
            
            if ((!sym.getName().contains("_")) && (!sym.getName().startsWith("entry")))
            {
                println(sym.getName() + " : " + sym.getAddress() + "\n");
                if (symit.hasNext())
                {   
                    SymbolIterator symittmp = symtab.getAllSymbols(false);
                    while (symittmp.hasNext())
                    {
                        if (symittmp.next()==sym)
                        {
                            Symbol next = symittmp.next();
                            int size = (int)next.getAddress().subtract(sym.getAddress());
                            dataAddr.put(sym.getName(),size);
                            break;                      
                        }
                    }
                }
            }            
        }
        */
        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                /*byte[] b = new byte[(int)secblock.getSize()];
                if (secblock.getBytes(secblock.getStart(),b) > -1)
                {
                    println("[ "+ secblock.getName() +" ] : bytes retreived");
                }
                int indtmp = 0;
                for (int i = 0;i<b.length;i++) {
                    if (b[i]==0) 
                    {
                        printf("\nNew string : ");
                        byte[] btmp = getSliceOfArray(b,indtmp,i);

                        for (int j = 0;j<btmp.length;j++) printf(String.format("%02x", btmp[j]));
                        //String string = new String(btmp);
                        //println(string);
                        if
                        indtmp = i;
                    }
                }
                int cpt = 0;
                */

                /* TODO : imports */ 

                AddressSpace aSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
                ElfCompatibilityProvider elfCompatProvider = new ElfCompatibilityProvider(currentProgram, false);
                Address thisAddr = aSpace.getAddress(mem.getLong(rttiBaseAddr.add(0x8)));
                String symbol = elfProvider.getReader().readTerminatedString(thisAddr.getOffset(), '\0');
                
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
}