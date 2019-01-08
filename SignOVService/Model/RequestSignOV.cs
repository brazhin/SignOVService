using SignService;

namespace SignOVService.Model
{
	public class RequestSignOV
	{
		public Mr Mr { get; set; }
		public string Soap { get; set; }
		public string Thumbprint { get; set; }
		public string Password { get; set; }
	}
}
