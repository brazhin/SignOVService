using SignOVService.Model.Cryptography;
using SignOVService.Model.Smev.Sign.Gosts.Const;
using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace SignOVService.Model.Smev.Sign.Gosts
{
	/// <summary>
	/// 
	/// </summary>
	public sealed class Gost3411XmlHash : HashAlgorithm
	{
		/// <summary>
		/// Дескриптор хэша
		/// </summary>
		[SecurityCritical]
		private IntPtr safeHashHandle;

		/// <summary>
		/// 
		/// </summary>
		public IntPtr HashHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get
			{
				return safeHashHandle;
			}
		}

		[SecuritySafeCritical]
		public Gost3411XmlHash()
		{
			HashSizeValue = Gost2001Const.HashSizeValue;
			IntPtr invalidHandle = IntPtr.Zero;
			CryptoProvider.CreateHash(CryptoProvider.TryGetGostProvider(), Gost2001Const.HashAlgId, ref invalidHandle);
			safeHashHandle = invalidHandle;
		}

		/// <summary>
		/// 
		/// </summary>
		[SecuritySafeCritical]
		public override void Initialize()
		{
			if (safeHashHandle != null	&& safeHashHandle != null)
			{
				//this.safeHashHandle.Dispose();  TODO:
			}

			IntPtr invalidHandle = IntPtr.Zero;
			CryptoProvider.CreateHash(CryptoProvider.TryGetGostProvider(), Gost2001Const.HashAlgId, ref invalidHandle);
			safeHashHandle = invalidHandle;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="rgb"></param>
		/// <param name="idStart"></param>
		/// <param name="cbSize"></param>
		[SecuritySafeCritical]
		protected override unsafe void HashCore(byte[] rgb, int idStart, int cbSize)
		{
			if (rgb != null && rgb.Length > 0 && cbSize > 0)
			{
				CryptoProvider.HashData(safeHashHandle, rgb, idStart, cbSize);
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return CryptoProvider.EndHash(safeHashHandle);
		}
	}
}
