using SignOVService.Model.Smev;
using System.Security.Cryptography.X509Certificates;

namespace SignOVService.Model
{
	public class RequestWithCert
	{
		public string Soap { get; set; }
		public object Certificate { get; set; }
		public MR Mr { get; set; }
	}
}
