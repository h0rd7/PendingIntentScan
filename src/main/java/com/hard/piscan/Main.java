package com.hard.piscan;

import org.apache.commons.cli.*;

public class Main {

    public static void main(String[] args) {
        if (args.length == 0) {
            args = new String[]{
                    "-f", "apks/video.apk",
                    "-a", "configs/android.jar",
            };
        }
        Options options = new Options();
        options.addOption("f", "file", true, "Apk file path to be analysed.");
        options.addOption("a", "android", true, "Android jar path.");
        CommandLineParser commandLineParser = new DefaultParser();
        try {
            CommandLine commandLine = commandLineParser.parse(options, args);
            if (commandLine.hasOption("f") && commandLine.hasOption("a")) {
                String apkPath = commandLine.getOptionValue("f");
                String androidJar = commandLine.getOptionValue("a");
                new PendingIntentChecker(apkPath, androidJar).doCheck();
            }
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }
}
