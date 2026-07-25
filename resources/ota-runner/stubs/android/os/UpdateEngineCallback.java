/*
 * Compile-only subset of AOSP android.os.UpdateEngineCallback.
 * SPDX-License-Identifier: Apache-2.0
 */
package android.os;

public abstract class UpdateEngineCallback {
    public UpdateEngineCallback() {}

    public abstract void onStatusUpdate(int status, float percent);

    public abstract void onPayloadApplicationComplete(int errorCode);
}
