using Microsoft.Win32.SafeHandles;
using SignService.CommonUtils;
using SignService.Unix.Api;
using SignService.Win.Api;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace SignService.Handle
{
	class SafeCSPHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeCSPHandle()
			: base(true)
		{
		}

		public SafeCSPHandle(IntPtr handle)
			: base(true)
		{
			SetHandle(handle);
		}

		public static SafeCSPHandle Null
		{
			get { return new SafeCSPHandle(IntPtr.Zero); }
		}

		protected override bool ReleaseHandle()
		{
			if(SignServiceUtils.IsUnix)
				CApiExtUnix.CryptReleaseContext(handle, 0);
			else
				CApiExtWin.CryptReleaseContext(handle, 0);

			return true;
		}

		// Changed by Ilya Mironov 2013.07.15
		// Add KeySpec property
		/// <summary>
		/// KeySpec property for CMSG_SIGNER_ENCODE_INFO class.
		/// </summary>
		public uint KeySpec { get; set; }
	}

	class SafeStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeStoreHandle()
			: base(true)
		{
		}

		public SafeStoreHandle(IntPtr handle)
			: base(true)
		{
			SetHandle(handle);
		}

		public static SafeStoreHandle Null
		{
			get { return new SafeStoreHandle(IntPtr.Zero); }
		}

		protected override bool ReleaseHandle()
		{
			if (SignServiceUtils.IsUnix)
				CApiExtUnix.CertCloseStore(handle, CApiExtConst.CERT_CLOSE_STORE_FORCE_FLAG);
			else
				CApiExtWin.CertCloseStore(handle, CApiExtConst.CERT_CLOSE_STORE_FORCE_FLAG);

			return true;
		}
	}

	class SafeCertContextHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeCertContextHandle()
			: base(true)
		{
		}

		public SafeCertContextHandle(IntPtr handle)
			: base(true)
		{
			SetHandle(handle);
		}

		public static SafeCertContextHandle Null
		{
			get { return new SafeCertContextHandle(IntPtr.Zero); }
		}

		protected override bool ReleaseHandle()
		{
			if(SignServiceUtils.IsUnix)
				CApiExtUnix.CertFreeCertificateContext(handle);
			else
				CApiExtWin.CertFreeCertificateContext(handle);

			return true;
		}
	}

	[SecurityCritical]
	internal sealed class SafeProvHandleCP : SafeHandleZeroOrMinusOneIsInvalid
	{
		private bool deleteOnClose_;

		internal bool DeleteOnClose
		{
			get
			{
				return this.deleteOnClose_;
			}
			set
			{
				this.deleteOnClose_ = value;
			}
		}

		internal static SafeProvHandleCP InvalidHandle
		{
			get
			{
				return new SafeProvHandleCP((IntPtr)0);
			}
		}

		private SafeProvHandleCP()
			: base(true)
		{
		}

		internal SafeProvHandleCP(IntPtr handle)
			: base(true)
		{
			this.SetHandle(handle);
		}

		internal SafeProvHandleCP(IntPtr handle, bool addref)
			: base(true)
		{
			if (!addref)
			{
				this.SetHandle(handle);
				return;
			}
			bool flag = false;
			int lastWin32Error = 0;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
			}
			finally
			{
				flag = CApiExtWin.CryptContextAddRef(handle, null, 0);//TODO
				lastWin32Error = Marshal.GetLastWin32Error();
				if (flag)
				{
					this.SetHandle(handle);
				}
			}
			if (!flag)
			{
				throw new CryptographicException(lastWin32Error);
			}
		}

		[SecurityCritical]
		protected override bool ReleaseHandle()
		{
			if (!this.DeleteOnClose)
			{
				if (SignServiceUtils.IsUnix)
					CApiExtUnix.CryptReleaseContext(this.handle, 0);
				else
					CApiExtWin.CryptReleaseContext(this.handle, 0);
			}
			else
			{
				if(SignServiceUtils.IsUnix)
					CApiExtUnix.CryptSetProvParam2(this.handle, 125, null, 0);//TODO
				else
					CApiExtWin.CryptSetProvParam2(this.handle, 125, null, 0);
			}

			return true;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal new void SetHandle(IntPtr handle)
		{
			base.SetHandle(handle);
		}
	}

	[SecurityCritical]
	internal sealed class SafeHashHandleCP : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeHashHandleCP InvalidHandle
		{
			get
			{
				return new SafeHashHandleCP((IntPtr)0);
			}
		}

		private SafeHashHandleCP()
			: base(true)
		{
		}

		internal SafeHashHandleCP(IntPtr handle)
			: base(true)
		{
			base.SetHandle(handle);
		}

		[SecurityCritical]
		protected override bool ReleaseHandle()
		{
			if(SignServiceUtils.IsUnix)
				CApiExtUnix.CryptDestroyHash(handle);
			else
				CApiExtWin.CryptDestroyHash(handle);

			return true;
		}
	}
}
