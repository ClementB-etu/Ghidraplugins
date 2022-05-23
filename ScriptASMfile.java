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

        //Read symtable before ! (name des var, size ... )
        
        SymbolTable symtab = currentProgram.getSymbolTable();
        SymbolIterator symit = symtab.getAllSymbols(false);
        
        Map<String, Int> instrInfo = new HashMap<String, String>();

        while (symit.hasNext())
        {   
            Symbol sym = symit.next();
            if ((!sym.getName().startsWith("_")) && (!sym.getName().startsWith("entry")))
            {
                println(sym.getName() + " : " + sym.getAddress() + "\n");
            }
        }

        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".text"))
            {
                pw.println(section  + secblock.getName());        
                pw.println(secblock.getStart());
            } 
            else if ((secblock.getName().equals(".data"))) 
            {
                pw.println(section  + secblock.getName() + " " +secblock.getSize());   
                byte[] b = new byte[(int)secblock.getSize()];
                if (secblock.getBytes(secblock.getStart(),b) > -1)
                {
                    println("[ "+ secblock.getName() +" ] :bytes retreived\n");
                }

                String string = new String(b);
                println("str : " + string); // A séparer (avec les infos dans symtable)

            } else if (secblock.getName().equals(".symtab")) 
            {
                pw.println(section  + secblock.getName() + " " +secblock.getSize());   
            }
        }

        pw.close();

        while ((listIt.hasNext())) {
            Instruction instr = listIt.next();
            println("instr : " + instr);
        }

    }
}
