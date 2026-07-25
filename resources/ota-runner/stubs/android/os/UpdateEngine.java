/*
 * Compile-only subset of AOSP android.os.UpdateEngine.
 * SPDX-License-Identifier: Apache-2.0
 */
package android.os;

public class UpdateEngine {
    public UpdateEngine() {}

    public boolean bind(UpdateEngineCallback callback) {
        return false;
    }

    public void cancel() {}

    public void resetStatus() {}

    public boolean unbind() {
        return false;
    }
}
