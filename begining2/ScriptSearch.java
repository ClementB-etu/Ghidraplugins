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

public class ScriptSearch extends GhidraScript {

    protected void add_bookmark_comment(Address addr, String text) {

        createBookmark(addr, "SearchForRedundancy", text);
        currentProgram.getListing().getCodeUnitAt(addr).setComment(CodeUnit.EOL_COMMENT, text);

    }

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

        /*
        * Map<String, Address> instrAddr : map associant Instruction et son adresse dans l'exécutable
        * Map<String, String[]> instrInfo : map associant Instruction et les différentes possibilités de son code machine
        */

        Map<Instruction, String> instrBytes = new HashMap<Instruction, String>();
        Map<String, String[]> instrInfo = new HashMap<String, String[]>();
        
     
        /*
        * ProcessBuilder : process used to run irasm and to retrieve the differents options of machine code for an instruction in log.txt
        */
        ProcessBuilder pb = new ProcessBuilder("ruby", "irasmCustomd.rb");
        pb.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/POC - SHAchecksum/Tools"));
        File log = new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/logV1.txt");

        if(!log.exists())
        {
            log.createNewFile();
        }
            
        pb.redirectOutput(log);
        Process proc = pb.start();
        OutputStream outStream = proc.getOutputStream();

        int cpt = 0;
        while ((listIt.hasNext())) {

            Instruction instr = listIt.next();
            Address instaddr = instr.getAddress();
            String byteseq = "";
            String strInstr = "";

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

                    bfinal[i] = bfinal[i].replace("f","").toUpperCase();
                    
                    if (bfinal[i].length() != 2)
                    {
                        bfinal[i] = '0' + bfinal[i];
                    }

                    byteseq += bfinal[i];
                }

                strInstr = instr.toString().replace("byte","").replace("dword","").replace("ptr","").replace("  "," ");
                //printf("strInstr : " + strInstr + "\n");
                instrBytes.put(instr,byteseq);
            }   
    
            String instrfin = strInstr + "\n";

            if (cpt != 0) 
                instrfin = "\n".concat(instrfin);
            else 
                cpt = 1;

            outStream.write(instrfin.getBytes());
            outStream.flush();

        }

        outStream.close();
        proc.waitFor();
    
        //Lecture de log.txt
        
        Scanner scan = new Scanner(log);
        String line;
        String infos;
        String[] arrOfInfos;
        
        while(scan.hasNextLine()) {
            line = scan.nextLine().trim();
            infos = "";

            if (line.startsWith("->") && (scan.hasNextLine()) && (!line.equals("->")))
            {
                line = line.replace("->","");
                infos = scan.nextLine().trim().replace("->","");

                while (infos.isEmpty())
                    infos = scan.nextLine().trim();

                arrOfInfos = infos.split(" ",0);

                instrInfo.put(line,arrOfInfos);

            }      
        }
        
        scan.close();
  
        int cptinstr = 0;   
        int cptv = 0; 
        for (Map.Entry<Instruction, String> entry : instrBytes.entrySet()) {

            String tmpInstr = entry.getKey().toString().replace("byte","").replace("dword","").replace("ptr","").replace("  "," ");
            String[] expectedCoding = instrInfo.get(tmpInstr);

            cptinstr++;

            if (instrInfo.containsKey(tmpInstr) && (!Arrays.asList(expectedCoding).contains("NON_VALID_INSTR")))
            {

                printf(" > " + entry.getKey() + "\n\t [ACTUAL CODING] : "+ entry.getValue());
            
                
                printf("\n\t [USUAL CODING] : ");
                for (int i = 0; i < expectedCoding.length;i++)
                {
                    printf (expectedCoding[i] + " ");
                    if (entry.getValue().equals(expectedCoding[i]))
                    {
                        printf("[YES] ");
                        cptv++;
                        break;

                    } else {
                        printf("[NO] ");
                        //String bookmarkString = "WARNING : " + entry.getKey() + " not coded the way we expected it to be";
                        //add_bookmark_comment(entry.getKey().getAddress(), bookmarkString);
                    }
                    
                }        

                printf("\n");
                
                
            } else {
                printf(" > " + entry.getKey() + " Error ?\n");
            }
            
        }
        printf("\n\n" + cptv + " 'correctly' coded instructions ( " + cptv + " / " + cptinstr +" )\n");

    }
}
