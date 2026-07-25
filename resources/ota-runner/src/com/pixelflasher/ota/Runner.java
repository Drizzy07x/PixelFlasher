/*
 * Copyright (C) 2026 PixelFlasher
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pixelflasher.ota;

import android.os.UpdateEngine;
import android.os.UpdateEngineCallback;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Minimal, architecture-neutral bridge to Android's system UpdateEngine API. */
public final class Runner {
    private static final int EX_USAGE = 64;
    private static final int EX_UNAVAILABLE = 69;
    private static final int STATUS_TIMEOUT_SECONDS = 10;

    private Runner() {}

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("ota_runner_usage");
            System.exit(EX_USAGE);
        }
        try {
            UpdateEngine engine = new UpdateEngine();
            String action = args[0];
            if ("status".equals(action)) {
                emitStatus(engine);
            } else if ("cancel".equals(action)) {
                engine.cancel();
            } else if ("reset".equals(action)) {
                engine.resetStatus();
            } else {
                System.err.println("ota_runner_action_unsupported");
                System.exit(EX_USAGE);
            }
        } catch (Throwable failure) {
            System.err.println("ota_runner_failed:" + failure.getClass().getSimpleName());
            System.exit(EX_UNAVAILABLE);
        }
    }

    private static void emitStatus(final UpdateEngine engine) throws InterruptedException {
        final CountDownLatch received = new CountDownLatch(1);
        final int[] status = new int[] {-1};
        final float[] progress = new float[] {-1.0f};
        UpdateEngineCallback callback =
                new UpdateEngineCallback() {
                    @Override
                    public void onStatusUpdate(int value, float percent) {
                        if (received.getCount() == 0) {
                            return;
                        }
                        status[0] = value;
                        progress[0] = percent;
                        received.countDown();
                    }

                    @Override
                    public void onPayloadApplicationComplete(int errorCode) {}
                };
        if (!engine.bind(callback)) {
            throw new IllegalStateException("bind");
        }
        try {
            if (!received.await(STATUS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("timeout");
            }
            System.out.println("CURRENT_OP=UPDATE_STATUS_" + statusName(status[0]));
            System.out.println("CURRENT_PROGRESS=" + Float.toString(progress[0]));
        } finally {
            engine.unbind();
        }
    }

    private static String statusName(int status) {
        switch (status) {
            case 0:
                return "IDLE";
            case 1:
                return "CHECKING_FOR_UPDATE";
            case 2:
                return "UPDATE_AVAILABLE";
            case 3:
                return "DOWNLOADING";
            case 4:
                return "VERIFYING";
            case 5:
                return "FINALIZING";
            case 6:
                return "UPDATED_NEED_REBOOT";
            case 7:
                return "REPORTING_ERROR_EVENT";
            case 8:
                return "ATTEMPTING_ROLLBACK";
            case 9:
                return "DISABLED";
            default:
                throw new IllegalArgumentException("status");
        }
    }
}
