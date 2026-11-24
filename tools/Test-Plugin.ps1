# Checks the Ashita 4.3 loader contract without initializing the plugin in FFXI.
param(
    [string]$PluginPath = (Join-Path $PSScriptRoot '..\dist\VanaView.dll'),
    [double]$ExpectedInterfaceVersion = 4.30
)

$ErrorActionPreference = 'Stop'
$PluginPath = (Resolve-Path -LiteralPath $PluginPath).Path

# FFXI plugins are x86; use a separate x86 process even from PowerShell 7/x64.
if ([IntPtr]::Size -ne 4) {
    $powershell32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    & $powershell32 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -PluginPath $PluginPath -ExpectedInterfaceVersion $ExpectedInterfaceVersion
    if ($LASTEXITCODE -ne 0) { throw 'Plugin compatibility check failed.' }
    return
}

if (-not ('VanaViewPluginCheck' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class VanaViewPluginCheck
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll")]
    private static extern bool FreeLibrary(IntPtr module);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate double GetVersion();
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr CreatePlugin(IntPtr args);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void DestroyPlugin(IntPtr plugin);

    private static Delegate Export(IntPtr module, string name, Type type)
    {
        IntPtr address = GetProcAddress(module, name);
        if (address == IntPtr.Zero)
            throw new InvalidOperationException("Missing required export: " + name);
        return Marshal.GetDelegateForFunctionPointer(address, type);
    }

    public static double Check(string path, double expected)
    {
        IntPtr module = LoadLibraryW(path);
        if (module == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot load x86 plugin: " + path);
        try
        {
            var version = (GetVersion)Export(module, "expGetInterfaceVersion", typeof(GetVersion));
            var create = (CreatePlugin)Export(module, "expCreatePlugin", typeof(CreatePlugin));
            var destroy = (DestroyPlugin)Export(module, "expDestroyPlugin", typeof(DestroyPlugin));
            double actual = version();
            if (Math.Abs(actual - expected) > 0.000001 || double.IsNaN(actual))
                throw new InvalidOperationException("Interface mismatch: expected " + expected + ", got " + actual);
            IntPtr instance = create(IntPtr.Zero);
            if (instance == IntPtr.Zero)
                throw new InvalidOperationException("expCreatePlugin returned null.");
            destroy(instance);
            return actual;
        }
        finally { FreeLibrary(module); }
    }
}
'@
}

$version = [VanaViewPluginCheck]::Check($PluginPath, $ExpectedInterfaceVersion)
Write-Host "PASS: x86 load, required exports, interface $version, create/destroy: $PluginPath"
Write-Host 'Initialize, rendering, memory patches and zone changes still require an in-game test.'
