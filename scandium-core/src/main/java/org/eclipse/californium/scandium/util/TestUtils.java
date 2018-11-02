package org.eclipse.californium.scandium.util;

import java.util.Timer;

public class TestUtils {
    public static int getDatagramsPackages() {
        return DatagramsPackages;
    }

    public static void DatagramsPackagesIncrease() {
        DatagramsPackages++;
    }

    public static long getStartTime() {
        return startTime;
    }

    public static void setStartTime(long startTime) {
        if (TestUtils.startTime == 0)
            TestUtils.startTime = startTime;
    }

    public static long getEndTime() {
        return endTime;
    }

    public static void setEndTime(long endTime) {
        if (TestUtils.endTime == 0)
            TestUtils.endTime = endTime;
    }

    // 数据报数量
    public static int DatagramsPackages = 0;
    // 开始时间
    public static long startTime = 0;
    // 结束时间
    public static long endTime = 0;
}
