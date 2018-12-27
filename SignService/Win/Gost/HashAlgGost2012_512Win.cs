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
	[ComVisible(true)]
	public sealed class HashAlgGost2012_512Win : HashAlgorithm
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

		public HashAlgGost2012_512Win()
		{
			this.HashSizeValue = Gost3411_12_512Consts.HashSizeValue;
			SafeHashHandleCP invalidHandle = SafeHashHandleCP.InvalidHandle;
			Win32ExtUtil.CreateHash(Win32ExtUtil.StaticGost2012_512ProvHandle, Gost3411_12_512Consts.HashAlgId, ref invalidHandle);
			this.safeHashHandle = invalidHandle;
		}

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

		[SecuritySafeCritical]
		protected override void HashCore(byte[] rgb, int ibStart, int cbSize)
		{
			if (rgb != null && rgb.Length > 0 && cbSize > 0)
			{
				Win32ExtUtil.HashData(this.safeHashHandle, rgb, ibStart, cbSize);
			}
		}

		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return Win32ExtUtil.EndHash(this.safeHashHandle);
		}

		[SecuritySafeCritical]
		public override void Initialize()
		{
			if (this.safeHashHandle != null
				&& !this.safeHashHandle.IsClosed)
			{
				this.safeHashHandle.Dispose();
			}

			SafeHashHandleCP invalidHandle = SafeHashHandleCP.InvalidHandle;
			Win32ExtUtil.CreateHash(Win32ExtUtil.StaticGost2012_512ProvHandle, Gost3411_12_512Consts.HashAlgId, ref invalidHandle);
			this.safeHashHandle = invalidHandle;
		}
	}
}
