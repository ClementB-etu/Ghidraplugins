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
//My third script - version 3.0 - Trying to deobfuscate functions
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

public class FourthScript extends GhidraScript {

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

        Map<Instruction, String[]> instrBytes = new HashMap<Instruction, String[]>();
        Map<String, String[]> instrInfo = new HashMap<String, String[]>();

        /*
        * ProcessBuilder : process used to run irasm and to retrieve the differents options of machine code for an instruction in log.txt
        */
        ProcessBuilder pb = new ProcessBuilder("ruby", "irasmCustomd.rb");
        pb.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/POC - SHAchecksum/Tools"));
        File log = new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/log.txt");

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

                    bfinal[i] = bfinal[i].replace("f","");

                    printf(bfinal[i]+ " - ");
                }
                printf("\n");
                instrBytes.put(instr,bfinal);
            }   
    
            String instrfin = instr + "\n";

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

            if (line.startsWith("->") && (scan.hasNextLine()))
            {
                line = line.substring(2); //Remove "->"
                infos = scan.nextLine().trim();
                while (infos.isEmpty())
                    infos = scan.nextLine().trim();

                arrOfInfos = infos.split(" ",0);

                instrInfo.put(line,arrOfInfos);

                //Traitement à faire sur arrOfInfos (être sur qu'il n'y a que du code machine)

            }      
        }
        
        scan.close();
        
        
        /*for (Map.Entry<Instruction, String[]> entry : instrBytes.entrySet()) {

            printf(" > " + entry.getKey() + " : [ACTUAL CODING] ");

            for (int i = 0;i<entry.getValue().length;i++)
            {
                printf(entry.getValue()[i] +" ");
            }

            if (instrInfo.containsKey(entry.getKey().toString()))
            {
                printf(" [USUAL CODING] : ");
                for (int i = 0; i < instrInfo.get(entry.getKey().toString()).length;i++)
                    printf (instrInfo.get(entry.getKey().toString())[i] + " ");
            }


            printf("\n");
                        

        }
        */
        
        /*for (Map.Entry<String, String[]> entry : instrInfo.entrySet()) {
            printf("  > " + entry.getKey() + "\n");
    
        }*/
    }
}
