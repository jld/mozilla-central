/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.gecko;


public class FennecTalosAssert implements Assert {
    
    public FennecTalosAssert() { }

    /**
     *  Write information to a logfile and logcat
     */
    public void dumpLog(String message) {
        FennecNativeDriver.log(FennecNativeDriver.LogLevel.INFO, message);
    }

    /** Write information to a logfile and logcat */
    public void dumpLog(String message, Throwable t) {
        FennecNativeDriver.log(FennecNativeDriver.LogLevel.INFO, message, t);
    }

    /**
     *  Set the filename used for dumpLog.
     */
    public void setLogFile(String filename) {
        FennecNativeDriver.setLogFile(filename);
    }

    public void setTestName(String testName) { }

    public void endTest() { }

    public void ok(boolean condition, String name, String diag) {
        if (!condition) {
            dumpLog("__FAIL" + name + ": " + diag + "__FAIL");
        }
    }

    public void is(Object a, Object b, String name) {
        boolean pass = (a == null ? b == null : a.equals(b));
        ok(pass, name, "got " + a + ", expected " + b);
    }
    
    public void isnot(Object a, Object b, String name) {
        boolean fail = (a == null ? b == null : a.equals(b));
        ok(!fail, name, "got " + a + ", expected not " + b);
    }

    public void ispixel(int actual, int r, int g, int b, String name) {
        throw new UnsupportedOperationException();
    }

    public void isnotpixel(int actual, int r, int g, int b, String name) {
        throw new UnsupportedOperationException();
    }

    public void todo(boolean condition, String name, String diag) {
        throw new UnsupportedOperationException();
    }

    public void todo_is(Object a, Object b, String name) {
        throw new UnsupportedOperationException();
    }
    
    public void todo_isnot(Object a, Object b, String name) {
        throw new UnsupportedOperationException();
    }

    public void info(String name, String message) {
        dumpLog(name + ": " + message);
    }
}
