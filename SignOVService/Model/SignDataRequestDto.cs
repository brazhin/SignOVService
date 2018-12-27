namespace SignOVService.Model
{
	public class SignDataRequestDto
	{
		public string Thumbprint { get; set; }
		public byte[] Data { get; set; }
	}
}
