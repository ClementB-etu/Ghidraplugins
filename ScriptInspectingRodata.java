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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.*;

import ghidra.program.model.data.StringDataType;

import ghidra.program.util.DefinedDataIterator;
import ghidra.app.util.XReferenceUtil;


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
                byte[] b = new byte[(int)secblock.getSize()];
                if (secblock.getBytes(secblock.getStart(),b) > -1)
                {
                    println("[ "+ secblock.getName() +" ] : bytes retreived");
                }
                
                /*File myObj = new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/results.txt");
                if (myObj.createNewFile()) {
                    println("File created: " + myObj.getName());
                }*/
                FileWriter myWriter = new FileWriter("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/results.txt");
     
                int indtmp = 8;
                
                /*for (int i = 8;i<b.length;i++) {
                    
                    monitor.setProgress(i);
                    byte[] btmp = getSliceOfArray(b,indtmp,i);
                    //String strtmp = new String(btmp);
                    String strtmp = "5bb2aad26ecb4f5aff83bfa8c8a1309267588fb9f5ee2041de61969ae20cc599af9fafdff6c47bd6bc82f67bb5c26dd3313438dd577018d22ba17f26552f33d791cfc714b5f9fa87b40902a166642bf686d6365f5dce3d7b9c06e6d9427a8b5496733bd084efeb48ff8ad8ad6201c407d6196a2d2d02ddbee52d6494eab6bf97bc0680d8365417fa2b31c381a7bfa34cdf0c67b85476273a0ce4326cdc876fc2113002f973e02ad0140c533e1cff42efd8e8e95ce9fdcece04f5ac8d67402bb0503a43c2ba1bdbf28fdc7bb3bcc68980f107a005977e5180bb0064768d9ae48a7abd9698f2661fd7019fbc70994c0be049eaf62704580b0415af9dec44dada562e412a0544bc2aa22aaa77b8552e7f188e91016861aa433c418318b9a6e8e92ca822911aa6470e5883cca322e11bbf60667ea441822b4a2ad0011d5be43059a1219ba646e887dd82688bedb122607aec69cc605c0ca396d42943b474fe20725ec05d9298bad8a46bf29e707f29171670ca9e3fa689c15d0ed777af0a2b265b44405d2916302b97908f818dcba35237f88c6c1bd59d2a42ecf765b5c816035ea122f8e77cd0c489c1d18625615d70e20b58dd412607d6bff9ae4615453c595b223c7bc7b0f26b3914fbf49d5d1eb2a6e205186f8d85a54dc0cf9232368a8aa4ca2997a3db3e505f45021088e76f9d8ec437251d86547ac1ba6bffe05a0c022f1ccf7a41625f211defbf123209b120d055622095a0d9b460847e62120e0956b7ad9d54f9253c58b9e29bcb0a3f0b3ca7c883428155d584a5131b0490456a210f6a129217ccbd62fdde";
                    Address addrtmp = find(strtmp);
                    if (addrtmp != null) {
                        myWriter.write("str found " + strtmp + " !\n");
                        println("str found " + strtmp + " !");
                        break;
                        //println("i : " + i  + " indtmp : " + indtmp);
                    } else {
                        myWriter.write("str : " + strtmp + " not found\n");
                        println("str : " + strtmp + " not found");
                        break;
                    }
                }*/
                Address addr = secblock.getStart();
                while (secblock.contains(addr))
                {
                    Data dat = currentProgram.getListing().getDataAt(addr);
                    long lgth = dat.getLength();
                    if (lgth == 1)
                    {
                        try 
                        {
                            currentProgram.getListing().createData​(addr, StringDataType.dataType);
                        } catch (Exception e) {
                            println(e);
                        }
                    }
                    println("[" + addr + "] data : " + dat.getValue() + " (length) "	+ lgth);
                    addr = addr.add(lgth);
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
}