using SignService.Win.Handles;
using SignService.Win.Utils;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace SignService.Win.Gost
{
	[ComVisible(true)]
	internal class HashMsApiUtil : HashAlgorithm
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

		int hashAlgId = 0;

		[SecuritySafeCritical]
		public HashMsApiUtil(int hashAlgId)
		{
			this.hashAlgId = hashAlgId;
			SafeHashHandleCP invalidHandle = SafeHashHandleCP.InvalidHandle;
			Win32ExtUtil.CreateHash(Win32ExtUtil.StaticMsProvHandle, hashAlgId, ref invalidHandle);
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
			Win32ExtUtil.CreateHash(Win32ExtUtil.StaticMsProvHandle, this.hashAlgId, ref invalidHandle);
			this.safeHashHandle = invalidHandle;
		}
	}
}
