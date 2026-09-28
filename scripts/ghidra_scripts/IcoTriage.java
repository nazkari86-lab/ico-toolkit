// Headless, read-only Ghidra summary for local CTF binaries.
// The script extracts defined strings, function names, and a bounded set of
// decompilations. It never invokes the imported program.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import java.io.File;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class IcoTriage extends GhidraScript {
    private static final int MAX_STRINGS = 10000;
    private static final int MAX_FUNCTIONS = 96;
    private static final int MAX_OUTPUT_CHARS = 2 * 1024 * 1024;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("IcoTriage requires an output file argument");
            return;
        }

        File destination = new File(args[0]);
        File parent = destination.getParentFile();
        if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
            throw new java.io.IOException("cannot create output directory");
        }

        try (PrintWriter output = new PrintWriter(new OutputStreamWriter(
                new java.io.FileOutputStream(destination), StandardCharsets.UTF_8))) {
            output.println("PROGRAM " + currentProgram.getName());
            output.println("LANGUAGE " + currentProgram.getLanguage().getLanguageID());

            Listing listing = currentProgram.getListing();
            DataIterator data = listing.getDefinedData(true);
            int strings = 0;
            while (data.hasNext() && strings < MAX_STRINGS) {
                monitor.checkCancelled();
                Data item = data.next();
                Object value = item.getValue();
                if (value instanceof String && !((String) value).isEmpty()) {
                    output.println("STRING " + item.getAddress() + " " + value);
                    strings++;
                }
            }

            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
                int count = 0;
                int writtenChars = 0;
                while (functions.hasNext() && count < MAX_FUNCTIONS && writtenChars < MAX_OUTPUT_CHARS) {
                    monitor.checkCancelled();
                    Function function = functions.next();
                    output.println("FUNCTION " + function.getEntryPoint() + " " + function.getName());
                    count++;

                    try {
                        DecompileResults result = decompiler.decompileFunction(function, 5, monitor);
                        if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                            String source = result.getDecompiledFunction().getC();
                            int remaining = MAX_OUTPUT_CHARS - writtenChars;
                            if (source.length() > remaining) {
                                source = source.substring(0, Math.max(0, remaining));
                            }
                            output.println(source);
                            writtenChars += source.length();
                        }
                    } catch (Exception exception) {
                        output.println("DECOMPILER_ERROR " + exception.getClass().getSimpleName());
                    }
                }
            } finally {
                decompiler.dispose();
            }
        }
    }
}
