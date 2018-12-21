using SignService;

namespace SignOVService.Model.Project
{
	public class SignServiceSettings : ISignServiceSettings
	{
		public string StoreLocation { get; set; }
		public string Thumbprint { get; set; }
		public CspType Csp { get; set; }
	}
}
