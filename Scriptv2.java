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
//Ghidra Script - Sanitizing, Inspecting & deobfuscating sanitized data in .rodata
//@category    Examples
//@keybinding  ctrl shift COMMA
//@toolbar    world.png

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.XReferenceUtil;
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
import java.util.*;
import java.util.stream.*;  
import java.util.zip.*;
import java.util.Map.Entry;
import java.io.*;
import java.nio.file.*;

public class Scriptv2 extends GhidraScript {

    /*
    *   Weigths used regarding the relevance of each indicator
    *
    *   symbolW : weight used when a string only contains [aA-zZ][0-9]
    *   lengthW : weight used when a string has a string which is a multiple from 4
    *   entropyW : weight used with the string's entropy
    *   nbrXREFW : weight used with the number of the XREF that the string has
    *
    */

    int entropyW = 12;
    int symbolW = 10;
    int nbrXREFW = 4;
    int lengthW = 2;
    

    /*
    * Name of the file created to be compiled and used to decode suspicious strings
    */
    String decodefilename = "decode.c";
    String resfilename = "res.txt";

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
        *   First, all the "blocks" (sections) bytes are retrieved
        *   We only focus on the ".rodata" section, because that's where strings used in the executable are stored
        */
        Listing listing = currentProgram.getListing();
        InstructionIterator listIt = listing.getInstructions(true);
        Memory mem = currentProgram.getMemory();
        ByteProvider byteProvider = new MemoryByteProvider(mem, currentProgram.getImageBase());
        MemoryBlock[] memblocksSections = mem.getBlocks();



        for (MemoryBlock secblock : memblocksSections) {
            if (secblock.getName().equals(".rodata"))
            {
                byte[] b = new byte[(int)secblock.getSize()];
                if (secblock.getBytes(secblock.getStart(),b) > -1)
                {
                    println("["+ secblock.getName() +"] : bytes retreived");
                }
                
                Address addr = secblock.getStart();

                //Iterates through .rodata to sanitize str (even with big strings that aren't analyzed by Ghidra's analyzer)
                while (secblock.contains(addr))
                {
                    Data dat = currentProgram.getListing().getDataAt(addr);
                    long lgth = dat.getLength();

                    /*
                    * Initially, "unsanitize" strings are 1byte-long while they aren't identified yet as proper string, but as a long sequence of byte
                    */
                    if (lgth == 1)
                    {
                        try 
                        {
                            currentProgram.getListing().createData​(addr, StringDataType.dataType);
                            //Datatype changed, so string has been created and dat (value, length ... )has changed

                            dat = currentProgram.getListing().getDataAt(addr);
                            lgth = dat.getLength();
                            //If lgth doesn't change, it isn't a string so codeunit needs to be clear in order not to crash during the next execution (if string exist at this addr, it crashes when creating string)
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

                double meanScore = 0;
                Map<String, Data> data = new HashMap<String, Data>();
                Map<String, Double> scores = new HashMap<String, Double>();
                Set<String> suspiciousstr = new HashSet<String>();
                Map<Address, Integer> flowcount = new HashMap<Address, Integer>();

                //At this point, all the potentially encoded strings are in 'Defined String' table, so we iterate through it
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

                        //println("dat : " + ((String) dat.getValue()) + "(number or letter ? : " + getNumberOrLetter(((String) dat.getValue())) + " )");
                        //println("dat : " + ((String) dat.getValue()) + "(appropriate length ? : " + getAppropriateLength(((String) dat.getValue())) + " )");
                        //println("dat : " + ((String) dat.getValue()) + "(entropy : " + getShannonEntropy(((String) dat.getValue())) + " )");
                        //println("dat : " + ((String) dat.getValue()) + "(nbr XREF : " + nbref + " )");

                        /*
                        *   Here, we calculate indicators for all strings, and associate a score to each depending on the weights we discussed at the begining
                        *   Then, we store the results
                        */

                        /*double scoresymbols = getNumberOrLetter((String) dat.getValue()) * this.symbolW;
                        double scorelenght = getAppropriateLength((String) dat.getValue()) * this.lengthW;
                        double scoreentropy = getShannonEntropy((String) dat.getValue()) * this.entropyW;
                        double scorexref = nbref * this.nbrXREFW;
                        double score = (scoresymbols + scorelenght + scoreentropy + scorexref);
                        meanScore += score;*/

                        String str = (String) dat.getValue();
                        double entr = getShannonEntropy(str);
                        meanScore += entr;

                        println("\n\nSTR entropy : " + entr + " ( " + str + " )");

                        /*
                        * working with compressed string to see any difference between encoded/non-encoded string
                        
                        String compressedstr = str + str + str;
                        
                        Deflater def = new Deflater();
                        def.setInput(compressedstr.getBytes("UTF-8")); 
                        def.finish();
                        byte compString[] = new byte[1024];
                        int compSize = def.deflate(compString);
                        //int compSize = def.deflate(compString, 3, 13, Deflater.FULL_FLUSH);
                        String finstr = new String(compString);
                        double ratio = entr/getShannonEntropy(finstr);
                        println("Compressed str size : " + compSize + " entr : " + getShannonEntropy(finstr) + "\nratio : " + ratio + "\n");
                        def.end();
                        */

                        /*
                        * working with subparts

                        int nbparts = str.length()/8;
                        List<Double> listentr = new ArrayList<Double>();
                        for (int i = 0; i<nbparts;i++) 
                        {   
                            int start = i*(str.length()/nbparts);
                            int end = (i+1)*((str.length()/nbparts));
                            String sub = str.substring(start,end);
                            Double subentr = getShannonEntropy(sub);
                            listentr.add(subentr);
                            
                            //println("SUBSTR entropy : " + subentr + " ( " + sub + " )");
                        }                                           
                        //println("MIN entr : " + Collections.min(listentr));
                        //println("MAX entr : " + Collections.max(listentr));
                        */

                        /*data.put((String) dat.getValue(), dat);
                        scores.put((String) dat.getValue(),score);*/

                        data.put(str, dat);
                        scores.put(str,entr);
                        
                    }
                }
                
                meanScore /= scores.size();
                println("mean entropy is : " + (meanScore));

                /*
                *  Now, we calculate the mean and the standard deviation
                */
                double etypeScore = 0;
                double treshold = 0;
                int nbdetect = 0;
                for (Map.Entry<String, Double> entry : scores.entrySet()) {
                    etypeScore += Math.pow((entry.getValue()-meanScore),2);
                }

                etypeScore = Math.sqrt(etypeScore / scores.size());
                println("standard deviation entropy is : " + etypeScore);

                //Comment choisir le seuil ?

                //
                treshold = meanScore + 1.9*(etypeScore/Math.sqrt(scores.size())) ; // Borne supérieur de l'intervalle de confiance à 95% (formule)
                println("treshold entropy is : " + treshold);

                for (Map.Entry<String, Double> entry : scores.entrySet()) {
                    
                    //This condition needs improvment (a lot of non-detected suspicious string)
                    if (entry.getValue() > treshold)
                    {
                        //println("\n[SUSPICIOUS] dat : " + entry.getKey() + "\n(score : " + entry.getValue() + " )\n");
                        suspiciousstr.add(entry.getKey());
                        nbdetect++;
                    } else {
                        //println("\ndat : " + entry.getKey() + "\n(score : " + entry.getValue() + " )\n");
                    }
                    
                }
                println(nbdetect + " detected (" + nbdetect+"/"+scores.size()+")");

                for (String s : suspiciousstr) {
                    
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
                            
                                if (nextinstr.getMnemonicString().equals("CALL"))
                                {
                                    //Retrieve address used by the CALL instruction
                                    Address[] flows = nextinstr.getFlows();
                                    for (int j = 0; j<flows.length;j++)
                                    {
                                        if (flowcount.containsKey(flows[j]))
                                        {
                                            flowcount.put(flows[j],flowcount.get(flows[j]) + 1);
                                        } else {
                                            flowcount.put(flows[j],1);
                                        }
                                    }
                                    
                                }
                            }   
                        } catch (Exception e) { }
                    }
                }
                
                try
                {
                    int max = Collections.max(flowcount.values());
                    
                    for (Map.Entry<Address, Integer> entry : flowcount.entrySet()) 
                    {
                        if (entry.getValue() == max)
                        {
                            analyseAddress(entry.getKey());
                        }
                    }
                } catch (Exception e) { }
                 
                ProcessBuilder pb = new ProcessBuilder("gcc", "-m32",decodefilename,"-o","decode");
                pb.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/"));   
                Process procgcc = pb.start();
                procgcc.waitFor();


                try
                {
                    String pathres = "/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/" + resfilename;
                    File resfile = new File(pathres);
                    FileWriter fwres = new FileWriter(resfile, false);
                    PrintWriter pwres = new PrintWriter(fwres);
                    
                    for (String s : suspiciousstr) {

                    ProcessBuilder pbdecode = new ProcessBuilder("./decode", s);
                    pbdecode.directory(new File("/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/"));   
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

    public int analyseAddress(Address addr)
    {
        Function fct = getFunctionAt(addr);
        //println("~ " + fct.getName()  + "  ~");
        Set<Function> fctcalled = fct.getCalledFunctions(monitor);
        Function fctsubstr = null;

        for (Function f : fctcalled)
        {
            if (!(f.getName().startsWith("FUN")) && !(f.getName().startsWith("_"))) {
                //println("~ " + f.getName() + " ~");
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
            String path = "/home/cytech/Desktop/ING2GSI1/STAGE/ERMBrussels/STAGE/Project/scripts/" + decodefilename;
            File code = new File(path);
            FileWriter fw = new FileWriter(code, false);
            PrintWriter pw = new PrintWriter(fw);
            pw.println(ccode);
            pw.close();
        } catch (Exception e) { 
            println("[ERROR] " + e.getMessage());
        }
       
        return 0;
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

    //Return 1 si s contient seulement [0-9] et [aA-zZ], 0 sinon
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

    //Return 1 if s est d'une longueur multiple de 4 (car chaque caractère encode utilise 2bytes(4 caractères))
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