package com.hard.piscan;

import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;
import soot.toolkits.scalar.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IntentAnalysis extends ForwardFlowAnalysis<Unit, Map<Local, Object>> {

    private final List<String> initSigs = new ArrayList<String>() {
        {
            add("<android.content.Intent: void <init>()>");
            add("<android.content.Intent: void <init>(java.lang.String)>");
            add("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>");
        }
    };

    private final List<String> intentWithPkgSigs = new ArrayList<String>() {
        {
            add("<android.content.Intent: void <init>(android.content.Context,java.lang.Class)>");
            add("<android.content.Intent: android.content.Intent setPackage(java.lang.String)>");
            add("<android.content.Intent: android.content.Intent setClassName(java.lang.String,java.lang.String)>");
            add("<android.content.Intent: android.content.Intent setComponent(android.content.ComponentName)>");
            add("<android.content.Intent: android.content.Intent setClassName(android.content.Context,java.lang.String)>");
            add("<android.content.Intent: android.content.Intent setClass(android.content.Context,java.lang.Class)>");
        }
    };

    private final Body body;
    private final Map<Local, ReturnStmt> returnStmtMap = new HashMap<>();

    public IntentAnalysis(Body body) {
        super(new BriefUnitGraph(body));
        this.body = body;
        doAnalysis();
    }

    public Object getRetAtStmt(Local local, Stmt stmt) {
        return getFlowBefore(stmt).get(local);
    }

    public String isRetIntentSafe() {
        for (Map.Entry<Local, ReturnStmt> entry : returnStmtMap.entrySet()) {
            Object ret = getRetAtStmt(entry.getKey(), entry.getValue());
            if (ret instanceof Pair) {
                String type = ((Pair<String, Object>) ret).getO1();
                if ("false".equals(type)) {
                    return type;
                } else if (!"true".equals(type)){
                    return "unknown";
                }
            }
        }
        return "true";
    }

    @Override
    protected void flowThrough(Map<Local, Object> in, Unit d, Map<Local, Object> out) {
        copy(in, out);
        if (d instanceof AssignStmt) {
            AssignStmt stmt = (AssignStmt) d;
            if (!stmt.containsInvokeExpr()) return;
            InvokeExpr expr = stmt.getInvokeExpr();
            SootMethod method = stmt.getInvokeExpr().getMethod();
            if (intentWithPkgSigs.contains(method.getSignature())) {
                if (expr instanceof VirtualInvokeExpr) {
                    out.put((Local) ((VirtualInvokeExpr) expr).getBase(), new Pair<>("true", null));
                } else if (expr instanceof SpecialInvokeExpr) {
                    out.put((Local) ((SpecialInvokeExpr) expr).getBase(), new Pair<>("true", null));
                }
            } else if (initSigs.contains(method.getSignature())) {
                if (expr instanceof VirtualInvokeExpr) {
                    out.put((Local) ((VirtualInvokeExpr) expr).getBase(), new Pair<>("false", null));
                } else if (expr instanceof SpecialInvokeExpr) {
                    out.put((Local) ((SpecialInvokeExpr) expr).getBase(), new Pair<>("false", null));
                }
            } else if ("android.content.Intent".equals(method.getReturnType().toString())) {
                out.put((Local) stmt.getLeftOp(), new Pair<>("return", method));
            }
        } else if (d instanceof InvokeStmt) {
            InvokeStmt stmt = (InvokeStmt) d;
            InvokeExpr expr = stmt.getInvokeExpr();
            String sig = stmt.getInvokeExpr().getMethod().getSignature();
            if (intentWithPkgSigs.contains(sig)) {
                if (expr instanceof VirtualInvokeExpr) {
                    out.put((Local) ((VirtualInvokeExpr) expr).getBase(), new Pair<>("true", null));
                } else if (expr instanceof SpecialInvokeExpr) {
                    out.put((Local) ((SpecialInvokeExpr) expr).getBase(), new Pair<>("true", null));
                }
            } else if (initSigs.contains(sig)) {
                if (expr instanceof VirtualInvokeExpr) {
                    out.put((Local) ((VirtualInvokeExpr) expr).getBase(), new Pair<>("false", null));
                } else if (expr instanceof SpecialInvokeExpr) {
                    out.put((Local) ((SpecialInvokeExpr) expr).getBase(), new Pair<>("false", null));
                }
            }
        } else if (d instanceof ReturnStmt) {
            ReturnStmt stmt = (ReturnStmt) d;
            if (stmt.getOp() instanceof Local)
                returnStmtMap.put((Local) stmt.getOp(), stmt);
        }
    }

    @Override
    protected Map<Local, Object> entryInitialFlow() {
        Map<Local, Object> ret = new HashMap<>();
        List<Local> paras = this.body.getParameterLocals();
        int len = paras.size();
        for (int i = 0; i < len; i++) {
            ret.put(paras.get(i), new Pair<>("param", i));
        }
        return ret;
    }

    @Override
    protected Map<Local, Object> newInitialFlow() {
        return new HashMap<>();
    }

    @Override
    protected void merge(Map<Local, Object> in1, Map<Local, Object> in2, Map<Local, Object> out) {
        out.clear();
        out.putAll(in1);
        out.putAll(in2);
    }

    @Override
    protected void copy(Map<Local, Object> source, Map<Local, Object> dest) {
        if (source == dest) {
            return;
        }
        dest.clear();
        dest.putAll(source);
    }
}
