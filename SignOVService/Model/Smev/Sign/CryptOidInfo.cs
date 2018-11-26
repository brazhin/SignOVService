using SignOVService.Model.Cryptography;
using System.Runtime.InteropServices;

namespace SignOVService.Model.Smev.Sign
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal struct CryptOidInfo
	{
		internal uint cbSize;
		[MarshalAs(UnmanagedType.LPStr)]
		internal string pszOID;
		internal string pwszName;
		internal uint dwGroupId;
		internal uint Algid;
		internal CRYPTOAPI_BLOB ExtraInfo;
	}
}
