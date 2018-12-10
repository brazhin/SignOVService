using SignService.Win.Handles;
using SignService.Win.Utils;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using static SignService.CApiExtConst;

namespace SignService.Win.Gost
{
	/// <summary>
	/// Класс для получения хэш функции по ГОСТ Р 34.11-2012, используя .NET.
	/// </summary>
	[ComVisible(true)]
	public sealed class Gost2012_256 : HashAlgorithm
	{
		[SecurityCritical]
		private SafeHashHandleCP safeHashHandle;

		[ComVisible(false)]
		public IntPtr HashHandle
		{
			[ComVisible(false)]
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get
			{
				return this.InternalHashHandle.DangerousGetHandle();
			}
		}

		internal SafeHashHandleCP InternalHashHandle
		{
			[SecurityCritical]
			get
			{
				return this.safeHashHandle;
			}
		}

		[SecuritySafeCritical]
		public Gost2012_256()
		{
			this.HashSizeValue = Gost3411_12_256Consts.HashSizeValue;
			SafeHashHandleCP invalidHandle = SafeHashHandleCP.InvalidHandle;
			Win32ExtUtil.CreateHash(Win32ExtUtil.StaticGost2012_256ProvHandle, Gost3411_12_256Consts.HashAlgId, ref invalidHandle);
			this.safeHashHandle = invalidHandle;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="disposing"></param>
		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			if (this.safeHashHandle != null
				&& !this.safeHashHandle.IsClosed)
			{
				this.safeHashHandle.Dispose();
			}

			base.Dispose(disposing);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="rgb"></param>
		/// <param name="ibStart"></param>
		/// <param name="cbSize"></param>
		[SecuritySafeCritical]
		protected override void HashCore(byte[] rgb, int ibStart, int cbSize)
		{
			if (rgb != null && rgb.Length > 0 && cbSize > 0)
			{
				Win32ExtUtil.HashData(this.safeHashHandle, rgb, ibStart, cbSize);
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return Win32ExtUtil.EndHash(this.safeHashHandle);
		}

		/// <summary>
		/// 
		/// </summary>
		[SecuritySafeCritical]
		public override void Initialize()
		{
			if (this.safeHashHandle != null
				&& !this.safeHashHandle.IsClosed)
			{
				this.safeHashHandle.Dispose();
			}

			SafeHashHandleCP invalidHandle = SafeHashHandleCP.InvalidHandle;
			Win32ExtUtil.CreateHash(Win32ExtUtil.StaticGost2012_256ProvHandle, Gost3411_12_256Consts.HashAlgId, ref invalidHandle);
			this.safeHashHandle = invalidHandle;
		}
	}
}
