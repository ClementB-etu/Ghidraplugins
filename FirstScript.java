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
//My first script - version 1.0.
//@category    Examples
//@menupath    Help.Examples.Hello World
//@keybinding  ctrl shift COMMA
//@toolbar    world.png

import ghidra.app.script.GhidraScript;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.listing.*;
import ghidra.program.database.mem.FileBytes;


import java.util.*;  
import java.util.Map;	 
import java.util.HashMap;
import java.util.List;
import java.lang.Math;

//import to read file
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;

public class FirstScript extends GhidraScript {

	@Override
	public void run() throws Exception {


		// You have to call initialize() in order for Ghidra to know to show the progress bar.
		monitor.initialize(10);

		for (int i = 0; i < 2; i++) {
			// Note: any script wishing to be responsive to a cancellation from the GUI needs to 
			// call checkCancelled()
			monitor.checkCanceled();

			Thread.sleep(1000); // pause a bit so we can see progress

			monitor.incrementProgress(10); // update the progress
			monitor.setMessage("Working on " + i); // update the status message			
			
		}

		int cpt = 0;
		double sum = 0.0;


		//CALCUL ENTROPIE

		try {
			Listing listing = currentProgram.getListing();
			InstructionIterator instructions = listing.getInstructions(true);

			while (instructions.hasNext())  {
				Instruction ins = instructions.next();
				
				String mnemo = ins.getMnemonicString();
				String instmp = ins.toString().substring(mnemo.length()); // SANS MOV,PUSH ...

				double entrotmp = getShannonEntropy(instmp);
				sum += entrotmp;
				cpt ++;
			}

			if (cpt == 0) 
				println("Votre fichier est vide");
			else 
				println("[->] ENTROPIE DE SHANNON : " + (sum/cpt));

		} catch (Exception e) {
			println("Veuillez ouvrir un fichier dans Ghidra pour l'analyser");
			e.printStackTrace();
		}

	}


	public static double log2(double x) {
		return (double) (Math.log(x) / Math.log(2));
	}

	public double getShannonEntropy(String s) {
		if (s == null) {
			return 0.0;
		}
		int n = 0;
		Map<Character, Integer> occ = new HashMap<>();
		for (int c_ = 0; c_ < s.length(); ++c_) {
			char cx = s.charAt(c_);
			if (occ.containsKey(cx)) {
				occ.put(cx, occ.get(cx) + 1);
			} else {
				occ.put(cx, 1);
			}
			++n;
		}
		double e = 0.0;
		for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
			char cx = entry.getKey();
			double p = (double) entry.getValue() / n;
			e += p * log2(p);
		}
		return -e;
	}


}
