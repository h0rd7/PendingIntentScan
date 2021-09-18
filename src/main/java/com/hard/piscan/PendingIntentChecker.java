package com.hard.piscan;

import soot.Main;
import soot.*;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.NullConstant;
import soot.jimple.Stmt;
import soot.options.Options;
import soot.toolkits.scalar.Pair;

import java.util.*;

public class PendingIntentChecker {

    private final List<String> excludePkgList = new ArrayList<String>(){
        {
            add("android.*");
            add("androidx.*");
            add("soot.*");
            add("java.*");
            add("javax.*");
            add("kotlin.*");
            add("kotlinx.*");
            add("retrofit.*");
            add("retrofit2.*");
            add("sun.*");
            add("org.*");
            add("uk.*");
            add("rx.*");
            add("dalvik.*");
            add("io.*");
            add("okio.*");
            add("okhttp.*");
            add("okhttp3.*");
            add("roboguice.util.*");
            add("de.greenrobot.*");
            add("com.google.android.material.*");
            add("com.google.gson.*");
            add("com.google.protobuf.*");
            add("com.google.firebase.*");
            add("com.squareup.*");
            add("com.nineoldandroids.*");
            add("com.airbnb.lottie.*");
            add("com.bumptech.glide.*");
            add("com.reactnativecommunity.*");
            add("com.facebook.litho.*");
            add("com.facebook.react.*");
            add("com.facebook.profilo.*");
            add("com.horcrux.svg.*");
            add("com.handmark.pulltorefresh.*");
            add("com.tekartik.sqflite.*");
            add("com.swmansion.gesturehandler.*");
            add("com.tbruyelle.rxpermissions.*");
            add("com.trello.rxlifecycle.*");
            add("com.alibaba.fastjson.*");
        }
    };

    private final List<String> piMethodSigs = new ArrayList<String>() {
        {
            add("<android.app.PendingIntent: android.app.PendingIntent getService(android.content.Context,int,android.content.Intent,int)>");
            add("<android.app.PendingIntent: android.app.PendingIntent getForegroundService(android.content.Context,int,android.content.Intent,int)>");
            add("<android.app.PendingIntent: android.app.PendingIntent getActivity(android.content.Context,int,android.content.Intent,int)>");
            add("<android.app.PendingIntent: android.app.PendingIntent getActivity(android.content.Context,int,android.content.Intent,int,android.os.Bundle)>");
            add("<android.app.PendingIntent: android.app.PendingIntent getActivityAsUser(android.content.Context,int,android.content.Intent,int,android.os.Bundle,android.os.UserHandle)>");
        }
    };

    private final int FLAG_IMMUTABLE = 1<<28;

    List<SootMethod> allIntentMethods = new ArrayList<>();

    public PendingIntentChecker(String apkPath, String androidJarPath) {
        initSoot(apkPath, androidJarPath);
    }

    public void doCheck() {
        Map<SootMethod, List<Stmt>> piStmts = new HashMap<>();
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (isExcludeClass(sootClass)) continue;
            List<SootMethod> methods = sootClass.getMethods();
            for (int i = 0; i < methods.size(); i++) {
                SootMethod method = methods.get(i);
                if (!method.isConcrete()) continue;
                try {
                    if (method.retrieveActiveBody() == null) continue;
                } catch (Exception e) {
//                    e.printStackTrace();
                    continue;
                }
                if (method.getActiveBody().toString().contains("android.content.Intent"))
                    allIntentMethods.add(method);
                List<Stmt> stmts = new ArrayList<>();
                for (Unit unit : method.getActiveBody().getUnits()) {
                    Stmt stmt = (Stmt) unit;
                    if (!stmt.containsInvokeExpr()) continue;
                    InvokeExpr invokeExpr = stmt.getInvokeExpr();
                    if (piMethodSigs.contains(invokeExpr.getMethod().getSignature())) {
                        Value flag = invokeExpr.getArg(3);
                        if (flag instanceof IntConstant) {
                            int val = ((IntConstant) flag).value;
                            if ((FLAG_IMMUTABLE & val) == FLAG_IMMUTABLE) continue;
                        }
                        Value intent = invokeExpr.getArg(2);
                        if (intent instanceof NullConstant) continue;
                        stmts.add(stmt);
                    }
                }
                if (!stmts.isEmpty())
                    piStmts.put(method, stmts);
            }
        }
//        System.out.println(allIntentMethods.size());
//        System.out.println(piStmts.size());
        Map<SootMethod, Stmt> unsafeRet = new HashMap<>();
        Map<SootMethod, Stmt> unknownRet = new HashMap<>();
        for (Map.Entry<SootMethod, List<Stmt>> entry : piStmts.entrySet()) {
            IntentAnalysis intentAnalysis = new IntentAnalysis(entry.getKey().getActiveBody());
            for (Stmt stmt : entry.getValue()) {
                Object ret = intentAnalysis.getRetAtStmt((Local) stmt.getInvokeExpr().getArg(2), stmt);
                if (ret instanceof Pair) {
                    String type = ((Pair<String, Object>) ret).getO1();
                    switch (type) {
                        case "return":
                            SootMethod method = ((Pair<String, SootMethod>) ret).getO2();
                            if (method.isConcrete()) {
                                String isRetIntentSafe = new IntentAnalysis(method.getActiveBody()).isRetIntentSafe();
                                if ("false".equals(isRetIntentSafe)){
                                    unsafeRet.put(entry.getKey(), stmt);
                                    break;
                                } else if ("true".equals(isRetIntentSafe)) {
                                    break;
                                }
                            }
                            unknownRet.put(entry.getKey(), stmt);
                            break;
                        case "param":
                            int index = ((Pair<?, Integer>) ret).getO2();
                            CallerElements caller = findCaller(entry.getKey(), index);
                            if (caller != null) {
                                Object callRet = new IntentAnalysis(caller.method.getActiveBody()).getRetAtStmt(caller.local, caller.stmt);
                                if (callRet instanceof Pair) {
                                    String type1 = ((Pair<String, Object>) callRet).getO1();
                                    if ("false".equals(type1)){
                                        unsafeRet.put(entry.getKey(), stmt);
                                        break;
                                    } else if ("true".equals(type1)){
                                        break;
                                    }
                                }
                            }
                            unknownRet.put(entry.getKey(), stmt);
                            break;
                        case "false":
                            unsafeRet.put(entry.getKey(), stmt);
                            break;
                        case "true":
                            break;
                        default:
                            unknownRet.put(entry.getKey(), stmt);
                    }
                } else {
                    unknownRet.put(entry.getKey(), stmt);
                }
            }
        }
        StringBuilder builder = new StringBuilder();
        if (!unsafeRet.isEmpty()) {
            builder.append("unsafe ret:\n");
            for (Map.Entry<SootMethod, Stmt> entry : unsafeRet.entrySet()) {
                builder.append("\t").append(entry.getKey()).append("\n");
                builder.append("\t\t").append(entry.getValue()).append("\n\n");
            }
        }
        if (!unknownRet.isEmpty()) {
            builder.append("unknown ret:\n");
            for (Map.Entry<SootMethod, Stmt> entry : unknownRet.entrySet()) {
                builder.append("\t").append(entry.getKey()).append("\n");
                builder.append("\t\t").append(entry.getValue()).append("\n\n");
            }
        }
        System.out.println(builder);
    }

    private CallerElements findCaller(SootMethod method, int index) {
        for (SootMethod intentMethod : allIntentMethods) {
            for (Unit unit : intentMethod.getActiveBody().getUnits()) {
                if (unit.toString().contains(method.getSignature())) {
                    Stmt stmt = (Stmt) unit;
                    Value value = stmt.getInvokeExpr().getArg(index);
                    if (value == null || value instanceof NullConstant) continue;
                    return new CallerElements(intentMethod, (Local) value, stmt);
                }
            }
        }
        return null;
    }

    private void initSoot(String apkPath, String androidJarPath) {
        G.reset();

        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_whole_program(true);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_force_android_jar(androidJarPath);
        Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
        Options.v().set_keep_offset(false);
        Options.v().set_keep_line_number(true);
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_exclude(excludePkgList);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_soot_classpath(androidJarPath);
        Main.v().autoSetOptions();
        Options.v().setPhaseOption("cg.spark", "on");
        Scene.v().loadNecessaryClasses();
//        PackManager.v().getPack("wjpp").apply();
    }

    private boolean isExcludeClass(SootClass sootClass) {
        if (sootClass.isPhantom()) return true;
        for (String exclude : excludePkgList) {
            if (sootClass.getName().startsWith(exclude.replace("*", ""))) return true;
        }
        return false;
    }

    class CallerElements {
        public SootMethod method;
        public Local local;
        public Stmt stmt;

        public CallerElements(SootMethod method, Local local, Stmt stmt) {
            this.method = method;
            this.local = local;
            this.stmt = stmt;
        }
    }

}
