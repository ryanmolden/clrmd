// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Runtime.Utilities;

namespace Microsoft.Diagnostics.Runtime.Implementation
{
    internal sealed class SymbolServerLocator : IBinaryLocator
    {
        public string SymbolPath { get; }

        private readonly string _cache = string.Empty;
        private readonly SymbolPathEntry[] _paths;
        private readonly Dictionary<string, Task<string?>> _queries = new Dictionary<string, Task<string?>>();

        public SymbolServerLocator()
            : this(null)
        {
        }

        public SymbolServerLocator(string? symbolPath)
        {
            symbolPath ??= string.Empty;

            SymbolPath = symbolPath;

            string[] entries = symbolPath.Split(';');

            List<SymbolPathEntry> paths = new List<SymbolPathEntry>(8);
            foreach (string entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry))
                    continue;

                string[] split = entry.Split('*');
                string location = split[split.Length - 1];

                string? cache = null;
                string? symbolServerDll = null;

                if (split.Length > 2)
                {
                    cache = split[split.Length - 2];

                    // TODO: Is this right? I don't put "cache" in my NT_SYMBOL_PATH, but I do still have a symbol cache
                    if (cache.Equals("cache", StringComparison.OrdinalIgnoreCase))
                    {
                        // TODO: How can this be null of cache.Equals was "cache"
                        if (cache == null)
                        {
                            // case: cache*c:\location
                            _cache = location;
                            continue;
                        }

                        // case: cache*c:\location*\\remote\path
                        _cache = cache;
                    }

                    if (cache.Equals("srv") || cache.Equals("svr"))
                        cache = null;

                    if(split.Length > 3)
                    {
                        // This handles an old format (used in some places) that is SYMSRV*<some dll name>*cache path*remote store
                        //
                        // In this case we must load <some dll name> and invoke the SymbolServer API contract that symsrv.dll lays out (and is undocumented). This allows
                        // people to redirect symbol server access through an arbitrary dll that implements a C-style interface. It sounds bizaare, but some systems inside
                        // Microsoft use this technique.
                        string temp = split[split.Length - 3];
                        if (!temp.Equals("srv") && !temp.Equals("svr") && temp.EndsWith(".dll"))
                        {
                            symbolServerDll = temp;
                        }
                    }
                }

                paths.Add(new SymbolPathEntry(cache, location, symbolServerDll));
            }

            _paths = paths.ToArray();
            if (string.IsNullOrWhiteSpace(_cache))
                _cache = Path.Combine(Path.GetTempPath(), "symbols");

            Directory.CreateDirectory(_cache);
        }

        public string? FindBinary(string fileName, ImmutableArray<byte> buildId, bool checkProperties = true) => null;

        public Task<string?> FindBinaryAsync(string fileName, ImmutableArray<byte> buildId, bool checkProperties = true) => Task.FromResult<string?>(null);

        public string? FindBinary(string fileName, int buildTimeStamp, int imageSize, bool checkProperties)
            => FindBinaryAsync(fileName, buildTimeStamp, imageSize, checkProperties).Result;

        public Task<string?> FindBinaryAsync(string path, int buildTimeStamp, int imageSize, bool checkProperties)
        {
            string fileName = Path.GetFileName(path);

            Task<string?>? result;
            string indexPath = GetIndexPath(fileName, buildTimeStamp, imageSize);
            lock (_queries)
                if (_queries.TryGetValue(indexPath, out result))
                    return result;

            // Check all local paths first
            if (CheckLocalFile(indexPath, path, buildTimeStamp, imageSize, checkProperties, out result))
                return result!;

            string fullPath = Path.Combine(_cache, indexPath);
            if (CheckLocalFile(indexPath, fullPath, buildTimeStamp, imageSize, checkProperties, out result))
                return result!;

            foreach (SymbolPathEntry entry in _paths)
            {
                if (entry.Cache != null)
                {
                    // Don't check the properties if it's in the right index location
                    fullPath = Path.Combine(entry.Cache, indexPath);
                    if (CheckLocalFile(indexPath, fullPath, buildTimeStamp, imageSize, checkProperties: false, out result))
                        return result!;

                    // if it's just some file on disk, check the properties
                    fullPath = Path.Combine(entry.Cache, fileName);
                    if (CheckLocalFile(indexPath, fullPath, buildTimeStamp, imageSize, checkProperties, out result))
                        return result!;
                }

                if (!entry.IsHttp)
                {
                    // Don't check the properties if it's in the right index location
                    fullPath = Path.Combine(entry.Location, indexPath);
                    if (CheckLocalFile(indexPath, fullPath, buildTimeStamp, imageSize, checkProperties, out result))
                        return result!;

                    // if it's just some file on disk, check the properties
                    fullPath = Path.Combine(entry.Location, fileName);
                    if (CheckLocalFile(indexPath, fullPath, buildTimeStamp, imageSize, checkProperties, out result))
                        return result!;
                }
            }

            lock (_queries)
            {
                if (_queries.TryGetValue(indexPath, out result))
                    return result;

                // Unfortunately this has to be called under a lock.  We need to make sure that multiple threads
                // do not race to download/copy the same file to a local path.  We will simply make sure that
                // FindBinaryFromServerAsync will 'await' before doing too much work.
                result = FindBinaryFromServerAsync(indexPath, buildTimeStamp, imageSize);
                _queries.Add(indexPath, result);

                return result;
            }
        }

        private async Task<string?> FindBinaryFromServerAsync(string indexPath, int buildTimeStamp, int imageSize)
        {
            // We assume that if we got the file from the symbol server that it matches the

            foreach (SymbolPathEntry entry in _paths)
            {
                if (entry.IsHttp)
                {
                    string? result = await FindBinaryFromServerAsync(entry.Location, entry.Cache ?? _cache, indexPath, entry.SymServerDll, buildTimeStamp, imageSize).ConfigureAwait(false);
                    if (result != null)
                        return result;
                }
            }

            return null;
        }

        private static async Task<string?> FindBinaryFromServerAsync(string server, string cache, string indexPath, string? symSrvDll, int buildTimeStamp, int imageSize)
        {
            // There are three ways symbol files can be indexed.  Start looking for each one.
            string fullDestPath = Path.Combine(cache, indexPath);

            if (symSrvDll != null)
            {
                return await GetPhysicalFileFromServerUsingSymSrvDllAsync(server, GetPathFromIndexPath(indexPath), symSrvDll, cache, buildTimeStamp, imageSize).ConfigureAwait(continueOnCapturedContext: false);
            }

            // First, check for the compressed location.  This is the one we really want to download.
            string compressedFilePath = indexPath.Substring(0, indexPath.Length - 1) + "_";
            string compressedFileTarget = Path.Combine(cache, compressedFilePath);

            TryDeleteFile(compressedFileTarget);
            Task<string?> compressedFilePathDownload = GetPhysicalFileFromServerAsync(server, compressedFilePath, compressedFileTarget);

            // Second, check if the raw file itself is indexed, uncompressed.
            Task<string?> rawFileDownload = GetPhysicalFileFromServerAsync(server, indexPath, fullDestPath);

            // Last, check for a redirection link.
            string filePtrSigPath = Path.Combine(Path.GetDirectoryName(indexPath)!, "file.ptr");
            Task<string?> filePtrDownload = GetPhysicalFileFromServerAsync(server, filePtrSigPath, fullDestPath, true);

            // Handle compressed download.
            string? result = await compressedFilePathDownload.ConfigureAwait(false);
            if (result != null)
            {
                try
                {
                    // Decompress it
                    Command.Run("Expand " + Command.Quote(result) + " " + Command.Quote(fullDestPath));
                    Trace($"Found '{Path.GetFileName(indexPath)}' on server '{server}'.  Copied to '{fullDestPath}'.");
                    return fullDestPath;
                }
                catch (Exception e)
                {
                    Trace($"Exception encountered while expanding file '{result}': {e.Message}");
                }
                finally
                {
                    if (File.Exists(result))
                        File.Delete(result);
                }
            }

            // Handle uncompressed download.
            result = await rawFileDownload.ConfigureAwait(false);
            if (result != null)
            {
                Trace($"Found '{Path.GetFileName(indexPath)}' on server '{server}'.  Copied to '{result}'.");
                return result;
            }

            // Handle redirection case.
            string filePtrData = (await filePtrDownload.ConfigureAwait(false))?.Trim() ?? string.Empty;
            if (filePtrData.StartsWith("PATH:"))
                filePtrData = filePtrData.Substring(5);

            if (!filePtrData.StartsWith("MSG:") && File.Exists(filePtrData))
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(fullDestPath));
                    using (FileStream input = File.OpenRead(filePtrData))
                    using (FileStream output = File.OpenWrite(fullDestPath))
                        await input.CopyToAsync(output).ConfigureAwait(false);

                    Trace($"Found '{Path.GetFileName(indexPath)}' on server '{server}'.  Copied to '{fullDestPath}'.");
                    return fullDestPath;
                }
                catch (Exception)
                {
                    Trace($"Error copying from file.ptr: content '{filePtrData}' from '{filePtrSigPath}' to '{fullDestPath}'.");
                }
            }
            else if (!string.IsNullOrWhiteSpace(filePtrData))
            {
                Trace($"Error resolving file.ptr: content '{filePtrData}' from '{filePtrSigPath}'.");
            }

            Trace($"No file matching '{Path.GetFileName(indexPath)}' found on server '{server}'.");
            return null;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool SymbolServer([MarshalAs(UnmanagedType.LPWStr)] string? serverAndCachePath,
                                           [MarshalAs(UnmanagedType.LPWStr)] string fileName,
                                           IntPtr id,
                                           uint two,
                                           uint three,
                                           [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder filePath);

        private static Dictionary<string, IntPtr> LoadedSymServerDlls = new Dictionary<string, IntPtr>();

        private static Task<string?> GetPhysicalFileFromServerUsingSymSrvDllAsync(string server, string fileName, string symServerDll, string cachePath, int buildTimeStamp, int imageSize)
        {
            return Task.Run(() =>
                {
                    IntPtr moduleHandle;
                    lock (LoadedSymServerDlls)
                    {
                        if (!LoadedSymServerDlls.TryGetValue(symServerDll, out moduleHandle))
                        {
                            LoadedSymServerDlls[symServerDll] = moduleHandle = LoadLibrary(symServerDll);

                            if (moduleHandle == IntPtr.Zero)
                            {
                                Trace($"LoadLibrary on '{symServerDll}' returned: 0x'{Marshal.GetLastWin32Error()}.");
                                return (string?)null;
                            }
                        }
                    }

                    // We failed (on a previous call) to load the dll, we don't perpetually try, now we will just immediately fail
                    if(moduleHandle == IntPtr.Zero)
                        return (string?)null;

                    IntPtr symbolServerWAddress = GetProcAddress(moduleHandle, "SymbolServerW");
                    if (symbolServerWAddress == IntPtr.Zero)
                    {
                        Trace($"GetProcAddress on '{symServerDll}' for 'SymbolServerW' returned: 0x'{Marshal.GetLastWin32Error()}.");
                        return (string?)null;
                    }

                    StringBuilder outPath = new StringBuilder(260);
                    SymbolServer symbolServerWCallback = (SymbolServer)Marshal.GetDelegateForFunctionPointer(symbolServerWAddress, typeof(SymbolServer));
                    if (!symbolServerWCallback($"{cachePath}*{server}", fileName, (IntPtr)(int)buildTimeStamp, (uint)imageSize, three: 0, outPath))
                    {
                        Trace($"SymbolServerW in '{symServerDll}' for '{fileName}' returned: 0x'{Marshal.GetLastWin32Error()}.");
                        return (string?)null;
                    }

                    return outPath.ToString();
                });
        }

        private static async Task<string?> GetPhysicalFileFromServerAsync(string serverPath, string fileIndexPath, string fullDestPath, bool returnContents = false)
        {
            Uri fullUri = new Uri(serverPath + "/" + fileIndexPath.Replace('\\', '/'));
            try
            {
                using HttpClient http = new HttpClient();
                HttpResponseMessage msg = await http.GetAsync(fullUri).ConfigureAwait(false);

                if (!msg.IsSuccessStatusCode)
                    return null;

                if (returnContents)
                    return await msg.Content.ReadAsStringAsync().ConfigureAwait(false);

                Directory.CreateDirectory(Path.GetDirectoryName(fullDestPath));
                using FileStream fs = File.Create(fullDestPath);
                await msg.Content.CopyToAsync(fs).ConfigureAwait(false);
                return fullDestPath;
            }
            catch (HttpRequestException e)
            {
                Trace($"Encountered unexpected HttpClient exception: {e}");
                return null;
            }
        }

        private static void Trace(string msg)
        {
            System.Diagnostics.Trace.WriteLine(msg);
        }

        private bool CheckLocalFile(string indexPath, string fullPath, int buildTimeStamp, int imageSize, bool checkProperties, out Task<string?>? result)
        {
            // The path we found on disk may still be in the process of being copied from a remote source.
            // This could have come from another thread calling FindBinaryAsync in parallel.  Therefore we
            // have to carefully check the result.

            if (!File.Exists(fullPath))
            {
                result = null;
                return false;
            }

            lock (_queries)
            {
                if (_queries.TryGetValue(indexPath, out result))
                    return true;

                bool found = true;
                if (checkProperties)
                {
                    using PEImage img = new PEImage(File.OpenRead(fullPath));
                    unchecked
                    {
                        found = img.IndexFileSize == imageSize && img.IndexTimeStamp == buildTimeStamp;
                    }
                }

                if (found)
                {
                    result = Task.FromResult(fullPath)!;
                    _queries.Add(indexPath, result);
                    return true;
                }
            }

            result = null;
            return false;
        }

        private static void TryDeleteFile(string file)
        {
            if (File.Exists(file))
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                    // Ignore failure here.
                }
            }
        }

#pragma warning disable CA1308 // Normalize strings to uppercase, symbol server expects lowercase
        private static string GetPathFromIndexPath(string indexPath)
        {
            return indexPath.Substring(0, indexPath.IndexOf("\\"));
        }

        // NOTE: If this were to change GetPathFromIndexPath also needs to be changed to understand how to extract the orgiinal filename out of the formed index path
        private static string GetIndexPath(string fileName, int buildTimeStamp, int imageSize)
        {
            fileName = Path.GetFileName(fileName).ToLowerInvariant();
            return $"{fileName}\\{unchecked((uint)buildTimeStamp):x}{unchecked((uint)imageSize):x}\\{fileName}";
        }
#pragma warning restore CA1308 // Normalize strings to uppercase

        private readonly struct SymbolPathEntry
        {
            public string? Cache { get; }
            public string Location { get; }
            public bool IsHttp => Location.StartsWith("http:") || Location.StartsWith("https:");
            public bool IsLocal => !IsHttp && !new Uri(Location).IsUnc;
            public string? SymServerDll { get; }

            public SymbolPathEntry(string? cache, string location, string? symServerDll)
            {
                if (CreateCache(cache))
                    Cache = cache;
                else
                    Cache = null;

                Location = location;
                SymServerDll = symServerDll;
            }

            private static bool CreateCache(string? cache)
            {
                if (string.IsNullOrWhiteSpace(cache))
                    return false;

                if (Directory.Exists(cache))
                    return true;

                try
                {
                    Directory.CreateDirectory(cache);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }
    }
}
