using System;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SignOVService.Model.Cryptography;

namespace SignOVService.Controllers
{
	[Route("tests")]
	public class TestsController : Controller
	{
		private readonly CryptoProvider crypto;
		//private readonly ILogger<TestsController> log;

		public TestsController()
		{
			crypto = new CryptoProvider();
		}

		//public TestsController(ILogger<TestsController> log)
		//{
		//	this.log = log;
		//}

		[HttpGet("sign")]
		public IActionResult SignTest()
		{
			try
			{
				//log.LogDebug("Получили запрос на выполнение теста.");

				var crypto = new CryptoProvider();
				string gostThumbprint = "af976d0aca919d3df62649501e92145b5ed59967";//"8067b09d8564842d4285e400cf91c27c72cf4d0f";

				byte[] arr;
				using (var fs = System.IO.File.OpenRead("testSigned.xml"))
				{
					var memory = new MemoryStream();
					fs.CopyTo(memory);

					arr = memory.ToArray();
				}

				var sign = crypto.Sign(arr, gostThumbprint);

				return Ok(sign);
			}
			catch(Exception ex)
			{
				//log.LogError($"В результате теста возникла ошибка: Message:{ex.Message}, InnerException: {ex.InnerException.Message}.");
				return BadRequest(ex.Message);
			}
		}

		/// <summary>
		/// Тестовый метод для проверки подписания файла.
		/// Принимает файл в запросе MultipartFormData подписывает и возвращает файл с подписью
		/// </summary>
		/// <returns></returns>
		[HttpPost("signfile")]
		public IActionResult SignFile()
		{
			try
			{
				if (HttpContext.Request.Form.Files.Count <= 0)
					return BadRequest("Файлов для подписания не обнаружено.");

				var form = HttpContext.Request.Form;
				var file = HttpContext.Request.Form.Files[0];

				var stream = new MemoryStream();
				file.CopyTo(stream);

				string thumbprint = form["thumbprint"];

				if (string.IsNullOrEmpty(thumbprint))
				{
					return BadRequest("Не удалось получить значение thumbprint для поиска сертификата.");
				}

				var sign = crypto.Sign(stream.ToArray(), thumbprint);

				return File(sign, "application/x-msdownload", "sign.sig");
			}
			catch(Exception ex)
			{
				return BadRequest($"Internal Server Error: {ex.Message}.");
			}
		}
	}
}