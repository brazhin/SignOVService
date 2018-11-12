using SignOVService.Model.Smev;

namespace SignOVService.Model
{
	public class RequestSignOV
	{
		public MR Mr { get; set; }
		public string Soap { get; set; }
		public string Thumbprint { get; set; }
	}
}
