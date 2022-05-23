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
//Ghidra ScriptASMfile - Creation of an asm file using the disassembly code provided by ghidra
//@category    Examples
//@keybinding  ctrl shift COMMA
//@toolbar    world.png

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;

import ghidra.program.database.mem.FileBytes;

import ghidra.util.Msg;
import java.lang.Math;
import java.util.*;  
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.Charset;


public class ScriptASMfile extends GhidraScript {

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

        ElfHeader elfheader = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE,  byteProvider);
        
        File asm = new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/generated.asm");
        FileWriter fw = new FileWriter(asm, false);
        PrintWriter pw = new PrintWriter(fw);
        pw.println("global _start");

        String section = "\t\tsection ";

        MemoryBlock[] memblocksSections = mem.getBlocks();

        
        SymbolTable symtab = currentProgram.getSymbolTable();
        SymbolIterator symit = symtab.getAllSymbols(false);
        
        LinkedHashMap<String, Integer> dataAddr = new LinkedHashMap<String, Integer>();
        Map<Address, String> dataInfo = new HashMap<Address, String>();


        while (symit.hasNext())
        {   
            Symbol sym = symit.next();
            
            if ((!sym.getName().startsWith("_")) && (!sym.getName().startsWith("entry")))
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
                    pw.println("\t\t" + instr);
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
                    end = entry.getValue()-1;
                    byte[] btmp = Arrays.copyOfRange(b,start,start+end);
                    start = entry.getValue();

                    String string = new String(btmp);
                    pw.println( entry.getKey() +" : db\t'" + string + "',10");
                }              

            }
        }

        pw.close();

    }
}
