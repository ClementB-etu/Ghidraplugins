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

//Ghidra Script - Inspecting & deobfuscating strings (specific to AAD-Encoding)
//@category    Examples
//@author Clément BELLEIL

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedDataIterator;

import java.lang.Math;
import java.util.Map.Entry;
import java.util.*;
import java.util.stream.*;  
import java.io.*;
import java.nio.file.*;

public class ScriptAADencoding extends GhidraScript {

    /*
    * Name of the file created to be compiled and used to decode strings
    */
    String decodefilename = "decode.c";
    String resfilename = "res.txt";

    /*
    *   Weigths used regarding the relevance of each indicator
    *
    *   entropyW : weight used with the string's entropy
    *   symbolW : weight used when a string only contains [aA-zZ][0-9]
    *   nbrXREFW : weight used with the number of the XREF that the string has
    *   lengthW : weight used when a string has a string which is a multiple from 4
    */
    int entropyW = 12;
    int symbolW = 10;
    int nbrXREFW = 4;
    int lengthW = 2;

    /** Implemented method from `GhidraScript` used when the plugin is launched 
    * @return void
    */
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
        *   First, all the "blocks" bytes (sections) are retrieved
        *   We focus on the ".rodata" section, because that's where strings used in the executable are
        */
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        ByteProvider byteProvider = new MemoryByteProvider(mem, currentProgram.getImageBase());
        MemoryBlock[] memblocksSections = mem.getBlocks();
        
        /*
        * This part is useful to be sure that all strings are identified as such by the Ghidra Analyzer
        * Without it, some encoded string might be missing at the end
        */
        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                //b contains .rodata bytes
                byte[] b = new byte[(int)secblock.getSize()];                
                Address addr = secblock.getStart();

                //Iterates through .rodata by incrementing the value of addr to "create" str (big strings that aren't analyzed by Ghidra's analyzer)
                while (secblock.contains(addr))
                {
                    Data dat = currentProgram.getListing().getDataAt(addr);
                    long lgth = dat.getLength();

                    //Initially, "unrecognized" strings are 1byte-long while they aren't identified yet as proper string
                    if (lgth == 1)
                    {
                        try 
                        {
                            //This line converts long sequence of byte to string if it is
                            currentProgram.getListing().createData​(addr, StringDataType.dataType);

                            //Datatype changed, so string has been created and dat (value, length ... ) changed too
                            dat = currentProgram.getListing().getDataAt(addr);
                            lgth = dat.getLength();

                            //If lgth hasn't changed, `dat` isn't a string, so codeunit needs to be cleared for the program not to crash during the next execution
                            if (lgth == 1) 
                            {
                                currentProgram.getListing().clearCodeUnits(addr, addr.add(1), true);
                            }
                            addr = addr.add(lgth);

                        } catch (Exception e) {
                            println(e.getMessage());
                        }
                    } else {
                        addr = addr.add(lgth);
                    }  
                }

                /*
                * data : (string, data object of the string)
                * scores : (string, score of the string)
                * suspiciousstr : Set of strings that have a higher score than the threshold and are `suspicious`
                * refcount : (Address, amount of times that address is called with a string as parameter), the address with the maximum integer will be guessed as the decoding function
                */
                double meanScore = 0;
                Map<String, Data> data = new HashMap<String, Data>();
                Map<String, Double> scores = new HashMap<String, Double>();
                Set<String> suspiciousstr = new HashSet<String>();
                Map<Address, Integer> refcount = new HashMap<Address, Integer>();

                //At this point, all the potentially encoded strings are in the 'Defined String' table provided by Ghidra, so we iterate through it
                for (Data dat : DefinedDataIterator.definedStrings(currentProgram) ) {
                    Address strAddr = dat.getMinAddress();
                    if ((secblock.contains(strAddr)) && (dat.getLength()>5))
                    {                        
                        int nbref = 0;
                        ReferenceIterator refit = dat.getReferenceIteratorTo();
                        while(refit.hasNext())
                        {
                            nbref++;
                            refit.next();
                        }

                        /*
                        *   Score and weight 
                        *   
                        *   Here, we calculate indicators for all strings, and associate a score to each depending on the weights we discussed at the begining
                        *   Then, we store the results
                        */

                        String str = (String) dat.getValue();
                        double entr = getShannonEntropy(str);
                        double scorelenght = getAppropriateLength((String) dat.getValue()) * this.lengthW;
                        double scoresymbols = getNumberOrLetter((String) dat.getValue()) * this.symbolW;
                        double scoreentropy = entr * this.entropyW;

                        double score = (scoreentropy + scorelenght + scoresymbols);
                        meanScore += score;

                        data.put(str, dat);
                        scores.put(str,score);  
                    }
                }
                
                /*
                * Now, we calculate the mean and the standard deviation
                */

                double etypeScore = 0;
                double treshold = 0;
                int nbdetect = 0;

                meanScore /= scores.size();
                //println("mean score is : " + (meanScore));

                for (Map.Entry<String, Double> entry : scores.entrySet()) {
                    etypeScore += Math.pow((entry.getValue()-meanScore),2);
                }

                etypeScore = Math.sqrt(etypeScore / scores.size());
                //println("standard deviation entropy is : " + etypeScore);

                //The treshold is choosen in order to 'select' which strings are encoded and which aren't based on their entropy, their length ...
                treshold = meanScore - (etypeScore/Math.sqrt(scores.size())) ;
                //println("treshold entropy is : " + treshold);

                for (Map.Entry<String, Double> entry : scores.entrySet()) {
                    
                    //This condition needs improvment (few non-detected suspicious string)
                    if (entry.getValue() > treshold)
                    {
                        suspiciousstr.add(entry.getKey());
                        nbdetect++;
                    }
                    
                }
                println(nbdetect + " strings detected (" + nbdetect + "/"+scores.size() + ")");
                
                for (String s : suspiciousstr) {
                    
                    /*
                    * A reference is a couple (AddressFrom,AddressTo) 
                    * For each reference that has the string's address as AddressTo
                    * We look for the instruction at the AddressFrom
                    * If this instruction's mnemonic is a 'PUSH', the string is likely to be used as a parameter by a function
                    * So we look for the next CALL instruction 
                    * And we store the address of the called function
                    */

                    ReferenceIterator refit = data.get(s).getReferenceIteratorTo();
                    while(refit.hasNext())
                    {   
                        Address addrtmp = refit.next().getFromAddress();
                        Instruction i = getInstructionAt(addrtmp);
                        try
                        {
                            if (i.getMnemonicString().equals("PUSH"))
                            {
                                Instruction nextinstr = i.getNext();
                            
                                while (!nextinstr.getMnemonicString().equals("CALL"))
                                {
                                    nextinstr = i.getNext();  
                                }
                                //Retrieve address used by the CALL instruction
                                Address[] flows = nextinstr.getFlows();
                                for (int j = 0; j<flows.length;j++)
                                {
                                    if (refcount.containsKey(flows[j]))
                                    {
                                        refcount.put(flows[j],refcount.get(flows[j]) + 1);
                                    } else {
                                        refcount.put(flows[j],1);
                                    }
                                }
                            }   
                        } catch (Exception e) {
                            //println(e.getMessage());    
                        }
                    }
                }

                /*
                * By doing so, the supposed decoding function is the function that has the bigger value in `refcount`
                * So we retrieve the name, and the decompiled .c code for the user to look through the code
                */

                try
                {
                    int max = Collections.max(refcount.values());
                    
                    for (Map.Entry<Address, Integer> entry : refcount.entrySet()) 
                    {
                        if (entry.getValue() == max)
                        {
                            /*
                            * By analysing the address, we retrieve the decompiled code
                            * We custom it (by adding imports, changing variable type that are 'undefined' in the decompiled code)
                            * And we add a 'main' function, allowing us to pass a string as argument of the executable
                            * and so get the associate decoded string
                            */
                            analyseAddress(entry.getKey());
                        }
                    }
                } catch (Exception e) { 
                    println(e.getMessage());
                }
                
                /*
                * This part is used to compile the custom decompiled code of the decoding function
                */
                ProcessBuilder pb = new ProcessBuilder("gcc", "-m32",decodefilename,"-o","decode");
                Process procgcc = pb.start();
                procgcc.waitFor();

                try
                {
                    String pathres = resfilename;
                    File resfile = new File(pathres);
                    FileWriter fwres = new FileWriter(resfile, false);
                    PrintWriter pwres = new PrintWriter(fwres);
                    
                    /*
                    * We iterate through the suspicious strings, and pass it as argument of the executable 
                    * that we create by compiling the decoding function
                    * Then we write the result in a res.txt file
                    */

                    for (String s : suspiciousstr) {
                        ProcessBuilder pbdecode = new ProcessBuilder("./decode", s);
                        Process procdecode = pbdecode.start();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(procdecode.getInputStream()));
                        Stream<String> line = reader.lines();
                        String res = String.join("\n",line.collect(Collectors.toList()));

                        pwres.println(res);
                        procdecode.waitFor();                
                    }

                    pwres.close();

                } catch (Exception e) { 
                    println("[ERROR] " + e.getMessage());
                }               
            }
        }
    }


    /**
    * Add known type to the signature of the susposed decoding function, add imports and a main function in order to create a .c file that can be compiled and executed.
    *
    * @param addr address of the suposed decoding function 
    *
    * @return 0 if ok
    *
    * @throws Exception when the file is created, and when we
    *                   try to write our code into it
    *
    */
 
    public int analyseAddress(Address addr)
    {
        Function fct = getFunctionAt(addr);
        Set<Function> fctcalled = fct.getCalledFunctions(monitor);
        Function fctsubstr = null;

        for (Function f : fctcalled)
        {
            if (!(f.getName().startsWith("FUN")) && !(f.getName().startsWith("_"))) {
                fctsubstr = f;
                break;
            }
        }
        
        try
        {
            Parameter p = fct.getParameters()[0];
            p.setDataType(new PointerDataType(new CharDataType()),true,true,fct.getSignatureSource());

            for (Variable v : fct.getLocalVariables())
            {
                if (v.getDataType().isEquivalent(new Undefined1DataType()))
                {
                    v.setDataType(new ArrayDataType(new CharDataType(),4,1),fct.getSignatureSource());
                }
            }
            fctsubstr.setReturnType(new PointerDataType(new CharDataType()),fctsubstr.getSignatureSource());
        } catch (Exception e){ }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        DecompileResults ressubstr = ifc.decompileFunction(fctsubstr,0,monitor);
        ClangTokenGroup tokgroupsubstr = ressubstr.getCCodeMarkup();
        String ccodesubstr = tokgroupsubstr.toString();

        DecompileResults resdecode = ifc.decompileFunction(fct,0,monitor);
        ClangTokenGroup tokgroupdecode = resdecode.getCCodeMarkup();       
        String ccode = tokgroupdecode.toString();
        String convasmvol = "iVar1 = asmvol(uVar4);";

        String asmvol = "\nint asmvol (uint inputval){" +
                        "int outvalue;\n"+
                        "__asm__ volatile (\n"+
                        "\t\" mov %1,%%eax\\n\"\n"+
                        "\t\" aad\\n\"\n" +
                        "\t\"  mov %%eax,%0\\n\"\n" +
                        "\t:\"=r\" (outvalue) /* %0: Output variable list */\n" +
                        "\t:\"r\" (inputval) /* %1: Input variable list */\n" +
                        "\t:\"%eax\" /* Overwritten registers ('Clobber list') */);return outvalue;}\n";                
                
        String main =   "int main(int argc, char *argv[]){\n"+
                        " if (argc != 2) {fprintf(stderr, \"Usage: %s <String to Decode>\\n\", argv[0]);exit(EXIT_FAILURE);}"+
                        " printf(\"\\n-- START DECODING --\\nInput: %s\\n\", argv[1]);\n" +
                        " printf(\"Output: %s\\n-- END DECODING --\\n\\n\"," + fct.getName() + "(argv[1]));}\n";

        ccode = "#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n#include <sys/stat.h>\n" + ccodesubstr + ccode;

        //Trigger an error ("stack smashing detected")
        ccode = ccode.replace("if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {iVar3 = __stack_chk_fail_local();}","");
        //C-language conversion to use "byte"
        ccode = ccode.replace("byte","unsigned char");
        ccode = ccode.replace("FUN_000111d0","strlen");
        ccode = ccode.replace("FUN_00011280","calloc");
        ccode = ccode.replace("FUN_00011240","strtol");

        String delim = "(local_14,param_1,local_3c,4);";
        int index = ccode.indexOf(delim);
        ccode = ccode.substring(0, index + delim.length()) + convasmvol + ccode.substring(index + delim.length());

        ccode += asmvol + main;

        try
        {
            String path = decodefilename;
            File code = new File(path);
            FileWriter fw = new FileWriter(code, false);
            PrintWriter pw = new PrintWriter(fw);
            pw.println(ccode);
            println(" ** Code of the suposed decoding function on file : ~/" + decodefilename);
            println(" ** Results of the decoded strings : ~/" + resfilename);
            pw.close();
        } catch (Exception e) { 
            println("[ERROR] " + e.getMessage());
        }
       
        return 0;
    }


    /**
    * Calculate the base-2 logarithm of a double
    *
    *
    * @param x double 
    *
    * @return double which is the base-2 logarithm of x
    *
    */

    public static double log2(double x) {
		return (double) (Math.log(x) / Math.log(2));
	}

    /**
    * Calulate the ShannonEntropy of a string using `log2` function documented above and the known mathematical expression
    *
    * @param s string that we analyze
    *
    * @return the ShannonEntropy of s
    *
    */

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

    /**
    * To know if a string is composed only of [0-9][aA-zZ], which can be a sign of encoding
    *
    * @param s string that we analyze
    *
    * @return 1 if s is only composed of [0-9][aA-zZ], 0 if not
    *
    */

    public int getNumberOrLetter(String s) {
		if (s == null) {
			return 0;
		}
		for (int c_ = 0; c_ < s.length(); ++c_) {
			char cx = s.charAt(c_);
            int ascii = (int) cx;

            if (!(ascii>47 && ascii<58) && !(ascii>64 && ascii<91) && !(ascii>96 && ascii<123))
            {
                return 0;
            }
		}
	
		return 1;
	}

    /**
    * To know if the length of a string is a multiple of 4, which can be a sign of encoding
    *
    * @param s string that we analyze
    *
    * @return 1 if the length of a string is a multiple of 4, 0 if not
    *
    */

    public int getAppropriateLength(String s) {
		if (s == null) {
			return 0;
		}

		if ((s.length()%4) == 0)
        {
		    return 1;
        } else {
            return 0;
        }
	
	}
}