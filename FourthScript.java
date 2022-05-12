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
import java.util.List;
import java.util.Set;
import java.util.Iterator;

import java.io.File;
import java.io.PrintWriter;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;


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

        /* 
            ITERATES THROUGH INSTRUCTIONS
        */
            
        Listing listing = currentProgram.getListing();
        InstructionIterator listit = listing.getInstructions(true);

        ProcessBuilder pb = new ProcessBuilder("ruby", "irasm.rb");

        pb.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/POC - SHAchecksum/Tools"));

        var log = new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/log.txt");
        pb.redirectOutput(log);

        Process proc = pb.start();


            InputStream errStream = proc.getErrorStream();
            InputStream inStream = proc.getInputStream();
            OutputStream outStream = proc.getOutputStream();

        outStream.write("mov eax, 0x1\n".getBytes());
        outStream.flush();

        try (var reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) 
        {

            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

        }


        //p.destroy();

        /*
        while (listit.hasNext()) {
            Instruction instr = listit.next();

            Address addrinst = instr.getAddress();
            String mnemo = instr.getMnemonicString();
            

            try
            { 
                printf(instr + "\n");
                

            }
               
            catch(Exception e)
            {
			    e.printStackTrace();
            }
        }
        */
    }

}
