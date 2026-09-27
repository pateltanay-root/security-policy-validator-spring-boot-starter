package com.research.securitypolicy.source;

public class SecuritySourceLocation {

    private String className;

    private String methodName;

    private String filePath;

    private int lineNumber;


    public SecuritySourceLocation() {
    }


    public SecuritySourceLocation(
            String className,
            String methodName,
            String filePath,
            int lineNumber) {

        this.className = className;
        this.methodName = methodName;
        this.filePath = filePath;
        this.lineNumber = lineNumber;
    }


    public String getClassName() {
        return className;
    }


    public void setClassName(
            String className) {

        this.className = className;
    }


    public String getMethodName() {
        return methodName;
    }


    public void setMethodName(
            String methodName) {

        this.methodName = methodName;
    }


    public String getFilePath() {
        return filePath;
    }


    public void setFilePath(
            String filePath) {

        this.filePath = filePath;
    }


    public int getLineNumber() {
        return lineNumber;
    }


    public void setLineNumber(
            int lineNumber) {

        this.lineNumber = lineNumber;
    }


    @Override
    public String toString() {

        return "SecuritySourceLocation{"
                + "className='"
                + className
                + '\''
                + ", methodName='"
                + methodName
                + '\''
                + ", filePath='"
                + filePath
                + '\''
                + ", lineNumber="
                + lineNumber
                + '}';
    }
}