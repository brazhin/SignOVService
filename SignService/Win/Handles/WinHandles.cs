using Microsoft.Win32.SafeHandles;
using SignService.Win.Api;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace SignService.Win.Handles
{
	class SafeNTHeapHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeNTHeapHandle()
			: base(true)
		{ }

		public SafeNTHeapHandle(IntPtr handle)
			: base(true)
		{
			SetHandle(handle);
		}

		public static SafeNTHeapHandle Null
		{
			get { return new SafeNTHeapHandle(IntPtr.Zero); }
		}

		protected override bool ReleaseHandle()
		{
			Marshal.FreeHGlobal(handle);
			return true;
		}
	}

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
			CApiExtWin.CertCloseStore(handle, CApiExtConst.CERT_CLOSE_STORE_FORCE_FLAG);
			return true;
		}
	}

	class SafeMsgHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeMsgHandle()
			: base(true)
		{
		}

		public SafeMsgHandle(IntPtr handle)
			: base(true)
		{
			SetHandle(handle);
		}

		public static SafeMsgHandle Null
		{
			get { return new SafeMsgHandle(IntPtr.Zero); }
		}

		protected override bool ReleaseHandle()
		{
			CApiExtWin.CryptMsgClose(handle);
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
			CApiExtWin.CertFreeCertificateContext(handle);
			return true;
		}
	}

	[SecurityCritical]
	internal sealed class SafeKeyHandleCP : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeKeyHandleCP InvalidHandle
		{
			get
			{
				return new SafeKeyHandleCP((IntPtr)0);
			}
		}

		private SafeKeyHandleCP()
			: base(true)
		{
		}

		internal SafeKeyHandleCP(IntPtr handle)
			: base(true)
		{
			this.SetHandle(handle);
		}

		[SecurityCritical]
		protected override bool ReleaseHandle()
		{
			CApiExtWin.CryptDestroyKey(this.handle);
			return true;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal new void SetHandle(IntPtr handle)
		{
			base.SetHandle(handle);
		}
	}

	[SecurityCritical]
	internal sealed class SafeLocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeLocalAllocHandle() : base(true) { }

		// 0 is an Invalid Handle
		internal SafeLocalAllocHandle(IntPtr handle)
			: base(true)
		{
			SetHandle(handle);
		}

		internal static SafeLocalAllocHandle InvalidHandle
		{
			get { return new SafeLocalAllocHandle(IntPtr.Zero); }
		}

		[DllImport("kernel32.dll", SetLastError = true),
		SuppressUnmanagedCodeSecurity,
		ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static extern IntPtr LocalFree(IntPtr handle);

		override protected bool ReleaseHandle()
		{
			return LocalFree(handle) == IntPtr.Zero;
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
				flag = CApiExtWin.CryptContextAddRef(handle, null, 0);
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
				CApiExtWin.CryptReleaseContext(this.handle, 0);
			}
			else
			{
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
			CApiExtWin.CryptDestroyHash(handle);
			return true;
		}
	}
}
