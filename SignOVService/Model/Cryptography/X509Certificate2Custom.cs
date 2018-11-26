using System;
using System.Security.Cryptography.X509Certificates;

namespace SignOVService.Model.Cryptography
{
	public class X509Certificate2Custom : X509Certificate
	{
		public X509Certificate2Custom(IntPtr handle) : base(handle)
		{
			CertHandle = handle;
		}

		public X509Certificate2Custom(byte[] data, IntPtr handle) : base(data)
		{
			CertHandle = handle;
		}

		public IntPtr CertHandle { get; private set; }
	}
}
