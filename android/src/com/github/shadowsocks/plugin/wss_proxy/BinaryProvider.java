package com.github.shadowsocks.plugin.wss_proxy;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileNotFoundException;

// https://github.com/shadowsocks/shadowsocks-android/blob/master/plugin/README.md
public class BinaryProvider extends ContentProvider {
    private static final String PLUGIN = "wss-proxy";
    private static final String EXECUTABLE = "libwss-proxy.so";

    private String getExecutable() {
        return getContext().getApplicationInfo().nativeLibraryDir + "/" + EXECUTABLE;
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public String getType(Uri uri) {
        return "application/x-elf";
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(projection);
        String path = uri.getPath();
        String base = path == null ? "" : path.replaceAll("^/+|/+$", "");
        if (PLUGIN.startsWith(base)) {
            cursor.newRow().add("path", PLUGIN).add("mode", 0755);
        }
        return cursor;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (("/" + PLUGIN).equals(uri.getPath())) {
            return ParcelFileDescriptor.open(new File(getExecutable()), ParcelFileDescriptor.MODE_READ_ONLY);
        }
        throw new FileNotFoundException();
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        if ("shadowsocks:getExecutable".equals(method)) {
            Bundle bundle = new Bundle();
            bundle.putString("com.github.shadowsocks.plugin.EXTRA_ENTRY", getExecutable());
            return bundle;
        }
        return super.call(method, arg, extras);
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }
}
