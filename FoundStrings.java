
package pluginstring;

import java.lang.Math;
import java.util.*;
import java.util.Map.Entry;
import java.io.*;

import ghidra.program.util.string.*;


public class FoundStrings implements FoundStringCallback {

    public void stringFound (FoundString foundString) {
        System.out.println(foundString.toString());
    }
}