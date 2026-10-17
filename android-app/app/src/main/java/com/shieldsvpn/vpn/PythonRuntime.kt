package com.shieldsvpn.vpn

import android.content.Context
import android.util.Log
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

/**
 * Starts the embedded Python interpreter once per process and returns `pqvpn.android_client`.
 *
 * `configure()` points pqvpn at `libcrypto_pqvpn.so` (OpenSSL 3.5, packaged in jniLibs and extracted to
 * nativeLibraryDir) *before* anything imports `pqvpn.crypto.ossl`.  Call from a background thread: the
 * first start unpacks the Python standard library.
 */
object PythonRuntime {
    private const val TAG = "ShieldsPython"
    private var module: PyObject? = null

    @Synchronized
    fun androidClient(context: Context): PyObject {
        module?.let { return it }
        val app = context.applicationContext
        if (!Python.isStarted()) Python.start(AndroidPlatform(app))
        val m = Python.getInstance().getModule("pqvpn.android_client")
        val lib = m.callAttr("configure", app.applicationInfo.nativeLibraryDir).toString()
        Log.i(TAG, "Python ready; libcrypto at $lib")
        module = m
        return m
    }
}
