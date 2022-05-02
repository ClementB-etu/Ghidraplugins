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
//My second script - version 2.0 - Shannon Entropy by sections.
//@category    Examples
//@menupath    Help.Examples.Hello World
//@keybinding  ctrl shift COMMA
//@toolbar    world.png


import java.util.HashMap;
import java.util.Map;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

public class SecondScript extends GhidraScript {

    @Override
    protected void run() throws Exception {

        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

        //ELF HEADER & PROGRAM HEADERS ANALYSIS - SHANNON ENTROPY

        Memory memory = currentProgram.getMemory();
        ByteProvider byteProvider = new MemoryByteProvider(memory, currentProgram.getImageBase());
        Map<String, Double> results = new HashMap<String, Double>();
        Map<String, Double> resultsEcartcarre = new HashMap<String, Double>();
        
        try {

            /* 
                ELFheader

                Récupération des infos utiles (taille de l'eflHeader, nombre de program header ...)
                BinaryReader pour lire les `sizeelfheader` bytes et calculer l'entropie sur cette section
                
             */

            ElfHeader elfheader = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE,  byteProvider);

            // sizeelfheader == offsetforph sinon bytes entre les 2
            short sizeelfheader = elfheader.e_ehsize();
            long offsetforph = elfheader.e_phoff();
            short sizeprogheaders = elfheader.e_phentsize();
            short nbprogheadears = elfheader.e_phnum();

            BinaryReader reader = elfheader.getReader();
            byte[] byteselfH = reader.readNextByteArray(sizeelfheader);
            String elfh = new String(java.util.Arrays.toString(byteselfH));

            results.put("ELFHeader",getShannonEntropy(elfh));

            /* 
                Program headers

                Récupération de l'adresse de début des program headers (celle de fin du ELFHeader)
                Memoryblock avec tous les bytes de la première section (bytes ELFheader & Program headers)
                Map (idProgheader,byte[]) pour le calcul de l'entropie pour chaque program header
                Itération sur la map et affichage des résultats d'entropie
                
             */


            Address startaddr = currentProgram.getImageBase().add(offsetforph);
            MemoryBlock memblockProgHeaders = memory.getBlock(startaddr.add(sizeprogheaders));

            Map<Integer, byte[]> mapProgHeaders = new HashMap<Integer, byte[]>();

            for (int i = 0; i<nbprogheadears ; i++) 
            {
                // Taille et nombre connu des progheaders , donc adresse et nombre de bytes à extraire connus pour chaque Progheader
                byte[] bytesprogH = new byte[sizeprogheaders];
                memblockProgHeaders.getBytes(startaddr.add(sizeprogheaders*i), bytesprogH);
                mapProgHeaders.put(i,bytesprogH);

            }

            for (Map.Entry<Integer, byte[]> entry : mapProgHeaders.entrySet()) {

                String s = new String(java.util.Arrays.toString(entry.getValue()));
                results.put(("ProgramHeader" + entry.getKey()),getShannonEntropy(s));

            }

            /*

                Sections headers

                Récupération de tous les blocs du programme (1 MemoryBlock pour chaque) sauf le premier (ELFHeader & Program headers)
                Map (nomBloc, byte[]) pour le calcul de l'entropie pour chaque block
                Itération sur la map et affichage des résultats d'entropie                

            */

            MemoryBlock[] memblocksSections = currentProgram.getMemory().getBlocks();

            Map<String, byte[]> mapSecBlocks = new HashMap<String, byte[]>();

            for (MemoryBlock secblock : memblocksSections) {
                
                if (secblock != memblockProgHeaders) {
                    byte[] secbytes = new byte[ (int)secblock.getSize()];
                    secblock.getData().read(secbytes);
                    mapSecBlocks.put(secblock.getName(),secbytes);
                }
            
            }

            for (Map.Entry<String, byte[]> entry : mapSecBlocks.entrySet()) {

                String s = new String(java.util.Arrays.toString(entry.getValue()));
                results.put(entry.getKey(),getShannonEntropy(s));

            }

            /*

                Résultats

                Itération sur la map results et affichage des résultats d'entropie               
                Itération sur la map results et calcul / affichage de la moyenne des entropies               
                Itération sur la map resultsEcartcarre et calcul / affichage de l'écart type des entropies               

            */

            double moy = 0.0;

            for (Map.Entry<String, Double> entry : results.entrySet()) {
                
                double entropy = entry.getValue();
                String name = entry.getKey();

                //println(entropy + " ( "+ name + " )" );
                moy += entropy;

            }

            moy = moy / results.size();

            for (Map.Entry<String, Double> entry : results.entrySet()) {
                
                double entropy = entry.getValue();
                double ecartcarre = Math.pow((entropy-moy),2);
                String name = entry.getKey();

                resultsEcartcarre.put(name,ecartcarre);

            }
            
            double ecarttype = 0.0;
            double maxtmp = 0.0;

            for (Map.Entry<String, Double> entry : resultsEcartcarre.entrySet()) {

                double ecartcarre = entry.getValue();
                String name = entry.getKey();

                //max est l'écartcarré max d'une section à la moyenne si cette section à une entropie supérieure à la moyenne

                if ((ecartcarre > maxtmp) && (results.get(name) > moy)) {

                    maxtmp = ecartcarre;

                }
                ecarttype += ecartcarre;

            }

            final double max = maxtmp;
            ecarttype = ecarttype / resultsEcartcarre.size();

            resultsEcartcarre.keySet().forEach((key) -> {
                if (resultsEcartcarre.get(key) == max) {
                    println("This section : " + key + " might be malicious ! (entropy : " + results.get(key) + " )" );
                }
            });

            
        } catch (Exception e) {

            Msg.error(this, e.toString());
            byteProvider.close();
            return;

        }
    }

    /* 

        Méthodes pour le calcul de l'entropie de Shannon avec une chaine de caractère en paramètre

    */

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
