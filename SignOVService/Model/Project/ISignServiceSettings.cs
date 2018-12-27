using SignService;

namespace SignOVService.Model.Project
{
	public interface ISignServiceSettings
	{
		string StoreLocation { get; set; }
		string Thumbprint { get; set; }
		CspType Csp { get; set; }
	}
}
