namespace Utilities
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;

    public class WinHttp
    {
        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr WinHttpOpen(
            string pszAgentW,
            uint dwAccessType,
            string pszProxyW,
            string pszProxyBypassW,
            uint dwFlags
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr WinHttpConnect(
            IntPtr hSession,
            string pswzServerName,
            uint nServerPort,
            uint dwReserved
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr WinHttpOpenRequest(
            IntPtr hConnect,
            string pwszVerb,
            string pwszObjectName,
            string pwszVersion,
            string pwszReferrer,
            string ppwszAcceptTypes,
            uint dwFlags
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WinHttpSendRequest(
            IntPtr hRequest,
            string lpszHeaders,
            uint dwHeadersLength,
            IntPtr lpOptional,
            uint dwOptionalLength,
            uint dwTotalLength,
            UIntPtr dwContext
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WinHttpReceiveResponse(
            IntPtr hRequest,
            IntPtr lpReserved
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WinHttpQueryDataAvailable(
            IntPtr hRequest,
            out uint lpdwNumberOfBytesAvailable
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WinHttpReadData(
            IntPtr hRequest,
            IntPtr lpBuffer,
            uint dwNumberOfBytesToRead,
            out uint lpdwNumberOfBytesRead
        );

        [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WinHttpCloseHandle(IntPtr hInternet);
    }
}
