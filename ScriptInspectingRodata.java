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

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.CodeUnit;


import ghidra.util.Msg;
import java.lang.Math;
import java.util.HashMap;
import java.util.Map;

import java.io.*;
import java.util.Scanner;
import java.nio.file.*;
import java.util.Arrays;

/*
 * TODO
 * Traiter la dernière instruction ? (pas de next donc pas de taille)
 * Traiter une seule fois les instructions (si déjà dans la map = déjà traité)
 * Converir String en Instruction 
 * Traitement de arrOfInfos
 *
*/

public class Scriptv1 extends GhidraScript {

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

        
        SymbolTable symtab = currentProgram.getSymbolTable();
        SymbolIterator symit = symtab.getAllSymbols(false);
        
        LinkedHashMap<String, Integer> dataAddr = new LinkedHashMap<String, Integer>();
        Map<Address, String> dataInfo = new HashMap<Address, String>();

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

        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".text"))
            {
                pw.println(section  + secblock.getName());        
                pw.println("_start :");   
                while ((listIt.hasNext())) {
                    Instruction instr = listIt.next();
                    pw.println("\t\t" + instr.toString().replace("ptr",""));
                }
     
            } 
            else if ((secblock.getName().equals(".data"))) 
            {
                pw.println(section  + secblock.getName());   
                byte[] b = new byte[(int)secblock.getSize()];
                if (secblock.getBytes(secblock.getStart(),b) > -1)
                {
                    println("[ "+ secblock.getName() +" ] : bytes retreived\n");
                }
                
                int start = 0;
                int end = 0;
                for (Map.Entry<String, Integer> entry : dataAddr.entrySet())
                {   
                    println(entry.getKey() + " start : " + start + " end : " + end);
                    end = entry.getValue()-1;
                    byte[] btmp = Arrays.copyOfRange(b,start,start+end);
                    start = entry.getValue();

                    String string = new String(btmp);
                    pw.println( entry.getKey() +" : db\t'" + string + "',10");
                }              

            }
        }
}
