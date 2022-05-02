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

public class ThirdScript extends GhidraScript {

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
            ITERATES THROUGH FUNCTIONS 


        FunctionManager funmanag = currentProgram.getFunctionManager();
        FunctionIterator funit = funmanag.getFunctions(true);

            //AFTER 
            //FunctionIterator funit = funmanag.getExternalFunctions(true);
            

            while (funit.hasNext()) {
                Function f = funit.next();
                println("funit : " + f.getName());
                f.setComment("Commented " + f.getName() + " at " + f.getEntryPoint());
                
            }
        */

        /* 
            ITERATES THROUGH INSTRUCTIONS
        */
            
        Listing listing = currentProgram.getListing();
        InstructionIterator listit = listing.getInstructions(true);


        while (listit.hasNext()) {
            Instruction instr = listit.next();

            Address addrinst = instr.getAddress();
            String mnemo = instr.getMnemonicString();


            try
            { 
                println("[INSTR] " + mnemo + " at " + addrinst);

                Address[] susaddr = instr.getDefaultFlows();
               
                

                for (int i = 0; i< susaddr.length; i++)
                {
                    Function susfun = listing.getFunctionAt(susaddr[i]);
                    String susname = susfun.getName();
                    println("[USES] " + susname + " at " + susaddr[i]);
                }


            }
               
            catch(Exception e)
            {
			    e.printStackTrace();
            }
        }

        /* 
        
        
        SINKS 

        sinks = [					
        "strcpy",
        "memcpy",
        "gets",
        "memmove",
        "scanf",
        "strcpyA", 
        "strcpyW", 
        "wcscpy", 
        "_tcscpy", 
        "_mbscpy", 
        "StrCpy", 
        "StrCpyA",
        "lstrcpyA",
        "lstrcpy", 
	    ]

        */

    }

}
