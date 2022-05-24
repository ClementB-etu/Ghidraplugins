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
//Ghidra Script v2 - redundancy research
//@category    Examples
//@keybinding  ctrl shift COMMA
//@toolbar    world.png


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

import ghidra.program.database.mem.FileBytes;

import ghidra.util.Msg;
import java.lang.Math;
import java.util.*;  
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.Charset;


public class Scriptv2 extends GhidraScript {

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

        
        /*
        * Map<String, Address> instrAddr : map associant Instruction et son adresse dans l'exécutable
        * Map<String, String[]> instrInfo : map associant Instruction et les différentes possibilités de son code machine
        */


        Map<Instruction, String> instrBytes = new HashMap<Instruction, String>();
        Map<String, String> instrInfo = new HashMap<String, String>();
        int cptinstr = 0;
        int cptv = 0;
        while ((listIt.hasNext())) {

            Instruction instr = listIt.next();
            Address instaddr = instr.getAddress();
            String byteseq = "";

            if (listIt.hasNext())
            {
                Address instnextaddr = instr.getNext().getAddress();
                long size = instnextaddr.subtract(instaddr);

                MemBuffer bytes = instr.getInstructionContext().getMemBuffer();
                byte[] b = new byte[(int)size];
                bytes.getBytes(b,0);

                String[] bfinal = new String[(int)size];

                for (int i = 0; i< b.length;i++)
                {
                    bfinal[i] = Integer.toHexString(b[i]);

                    bfinal[i] = bfinal[i].replace("ff","").toUpperCase();
                    
                    if (bfinal[i].length() != 2)
                    {
                        bfinal[i] = '0' + bfinal[i];
                    }

                    byteseq += bfinal[i];
                }

                instrBytes.put(instr,byteseq);
            }   
    
            File log = new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/logV2.asm");
            FileWriter fw = new FileWriter(log, false);
            PrintWriter pw = new PrintWriter(fw);
            pw.println("[BITS 32]");
            String strInstr = instr.toString().replace("byte","").replace("dword","").replace("ptr","").replace("  "," ");

            pw.println(strInstr);
            pw.close();

            ProcessBuilder pbnasm = new ProcessBuilder("nasm", "-f", "bin","logV2.asm");
            pbnasm.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/"));
            Process procnasm = pbnasm.start();

            procnasm.waitFor();
            
            ProcessBuilder pbxxd = new ProcessBuilder("xxd","-ps", "-g","16","logV2");
            pbxxd.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/"));
            
            Process procxxd = pbxxd.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(procxxd.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                instrInfo.put(instr.toString(),line.toUpperCase());
            }

            procxxd.waitFor();
            
        }

       // Memory mem = currentProgram.getMemory();

        for (Map.Entry<Instruction, String> entry : instrBytes.entrySet()) {

            if ((instrInfo.containsKey(entry.getKey().toString())) && !(entry.getKey().toString().startsWith("J")))
            {
                String actualcod = entry.getValue().trim();
                String usualcod = instrInfo.get(entry.getKey().toString()).trim();     
                   
                if (actualcod.equals(usualcod))
                {
                    //printf(" [YES] \n");
                    cptv++;
                } else {
                    Address addr = entry.getKey().getAddress();

                    printf("\n > " + entry.getKey() + "\n\t [ACTUAL CODING] : "+ actualcod);

                    printf("\n\t [USUAL CODING] : " + usualcod + " ( " + addr +" )\n");

                    byte[] b = hexStringToByteArray(usualcod);
                    //printf(addr + " [NO] : ");  
                    String[] res = new String[b.length]; 
                    for (int i = 0; i<b.length;i++)
                    {
                        String str = "0x" + String.format("%02X", b[i]);
                        res[i]  = str;
                    }                

                    //editBytes(res,addr);

                }
                
                cptinstr++;
            }         
        }

        printf(cptv + " 'normally' coded instructions ( " + cptv + " / " + cptinstr + " )\n");
        
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public void editBytes(String[] b, Address startAddr) throws Exception {

		Address endAddr = null;
		Address activeAddr = null;
		Address codeEnd = null;
		boolean containedInBlock = false;

		while (containedInBlock == false) {
			monitor.checkCanceled();
			endAddr = startAddr.add(b.length - 1);
			activeAddr = startAddr;

			containedInBlock = currentProgram.getMemory().getBlock(activeAddr).contains(endAddr);
			if (containedInBlock == true) {
				break;
			}

			popup("Bytes entered cannot be contained in current memory block");
		}

		activeAddr = currentProgram.getListing().getCodeUnitContaining(activeAddr).getAddress();
		AddressSet addrSet = new AddressSet(activeAddr, endAddr);
		CodeUnitIterator iter = currentProgram.getListing().getCodeUnits(addrSet, true);

		AddressSet codeAddrSet = null;

		TreeMap<Address, DataType> addrToDataTypeMap = new TreeMap<>();
		TreeMap<Address, AddressSet> addrToCodeMap = new TreeMap<>();

		while (iter.hasNext()) {

			activeAddr = iter.next().getAddress();

			Data data = getDataAt(activeAddr);
			if (data != null) {
				DataType dataType = data.getDataType();
				addrToDataTypeMap.put(activeAddr, dataType);
				continue;
			}

			Instruction code = getInstructionContaining(activeAddr);
			if (code != null) {
				codeEnd = activeAddr.add(code.getLength() - 1);
				codeAddrSet = new AddressSet(activeAddr, codeEnd);
				addrToCodeMap.put(activeAddr, codeAddrSet);
				continue;
			}

			if (activeAddr.equals(endAddr)) {
				break;
			}
		}

		clearListing(startAddr, endAddr);

		try {
            for (int i = 0; i<b.length;i++)
            {      
                //printf(Integer.parseInt(b[i]));
                //printf("String to add :  " + Integer.parseInt(b[i]) + "\n");
                //printf(" type byte : " + b[i].getClass());
			    setByte(startAddr, (byte) Integer.parseInt(b[i]));
            }
		}
		catch (Exception e) {
			popup("Bytes cannot be set on uninitialized memory");
			return;
		}

		for (Entry<Address, DataType> entry : addrToDataTypeMap.entrySet()) {
			try {
				createData(entry.getKey(), entry.getValue());
			}
			catch (CodeUnitInsertionException e) {
				//leaves bytes undefined if there is no 00 byte at the end to
				//make a null terminated string 
				return;
			}
		}

		for (Entry<Address, AddressSet> entry : addrToCodeMap.entrySet()) {
			DisassembleCommand cmd = new DisassembleCommand(entry.getKey(), entry.getValue(), true);
			cmd.applyTo(currentProgram, monitor);
		}
        
    }

    protected void add_bookmark_comment(Address addr, String text) {
        createBookmark(addr, "SearchForRedundancy", text);
        currentProgram.getListing().getCodeUnitAt(addr).setComment(CodeUnit.EOL_COMMENT, text);
    }
}
