using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SignOVService.Model;
using SignService;

namespace SignOVService.Controllers
{
	[Route("cryptography")]
	public class TestsController : Controller
	{
		private readonly SignServiceProvider provider;

		public TestsController(ILoggerFactory logggerFactory, SignServiceProvider provider)
		{
			this.provider = provider;
		}

		/// <summary>
		/// Тестовый метод создания открепленной подписи
		/// </summary>
		/// <returns></returns>
		[HttpPost("signdatafile")]
		public IActionResult SignDataFile()
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

				// Подписываем данные
				var sign = provider.Sign(stream.ToArray(), thumbprint);

				return Ok(sign);
			}
			catch (Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод подписи данных
		/// </summary>
		/// <param name="request"></param>
		/// <returns></returns>
		[HttpPost("signdata")]
		public IActionResult SignDataRequest([FromBody] SignDataRequestDto request)
		{
			try
			{
				// Подписываем данные
				var sign = provider.Sign(request.Data, request.Thumbprint);
				return Ok(Convert.ToBase64String(sign));
			}
			catch (Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}

		/// <summary>
		/// Тестовый метод создания открепленной подписи
		/// </summary>
		/// <returns></returns>
		[HttpPost("getsignfile")]
		public IActionResult GetSignFile()
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

				// Подписываем данные
				var sign = provider.Sign(stream.ToArray(), thumbprint);

				return File(sign, "application/x-msdownload", "sign.sig");
			}
			catch (Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}

		/// <summary>
		/// Тестовый метод проверки открепленной подписи
		/// </summary>
		/// <returns></returns>
		[HttpPost("verifysign")]
		public IActionResult VerifyDetachedSign()
		{
			try
			{
				if (HttpContext.Request.Form.Files.Count <= 0)
					return BadRequest("Файлов для подписания не обнаружено.");

				var files = HttpContext.Request.Form.Files;

				var sign = files.FirstOrDefault(x => Path.GetExtension(x.FileName) == ".sig");
				if (sign == null)
				{
					return BadRequest("Не удалось найти файл с расширением .sig (подпись) в запросе.");
				}

				var data = files.FirstOrDefault(x => Path.GetExtension(x.FileName) != ".sig");
				if (data == null)
				{
					return BadRequest("Не удалось найти файл с данными в запросе.");
				}

				var signStream = new MemoryStream();
				sign.CopyTo(signStream);

				var dataStream = new MemoryStream();
				data.CopyTo(dataStream);

				X509Certificate2 cert = null;
				var result = provider.VerifyDetachedMessage(signStream.ToArray(), dataStream.ToArray(), false, ref cert);

				return Ok(new
				{
					VerifyResult = result,
					CertSubject = cert.Subject
				});
			}
			catch(Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод создания хэш
		/// </summary>
		/// <returns></returns>
		[HttpPost("createhash")]
		public IActionResult CreateHash()
		{
			try
			{
				if (HttpContext.Request.Form.Files.Count <= 0)
					return BadRequest("Файлов для рассчета хэш не обнаружено.");

				var form = HttpContext.Request.Form;
				var file = HttpContext.Request.Form.Files[0];

				var stream = new MemoryStream();
				file.CopyTo(stream);
				stream.Position = 0;

				string thumbprint = form["thumbprint"];

				if (string.IsNullOrEmpty(thumbprint))
				{
					return BadRequest("Не удалось получить значение thumbprint для поиска сертификата.");
				}

				// Подписываем данные, необходимо убедиться что значение Stream.Position = 0
				var hash = provider.CreateHash(stream, thumbprint);

				return Ok(hash);
			}
			catch (Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод подписи xml
		/// </summary>
		/// <param name=""></param>
		/// <returns></returns>
		[HttpPost("signsoap")]
		public IActionResult SignSoap([FromBody] RequestSignOV request)
		{
			try
			{
				var signedXml = provider.SignSoap(request.Soap, request.Mr, request.Thumbprint, "");
				return Ok(signedXml);
			}
			catch(Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод подписи xml
		/// </summary>
		/// <param name=""></param>
		/// <returns></returns>
		[HttpPost("signsoapfile")]
		public IActionResult SignSoapFile()
		{
			try
			{
				if (HttpContext.Request.Form.Files.Count <= 0)
					return BadRequest("Файлов для подписания не обнаружено.");

				var form = HttpContext.Request.Form;
				var file = HttpContext.Request.Form.Files[0];

				var mr = Int32.Parse(form["Mr"]);
				var thumbprint = form["Thumbprint"];
				var password = form["Password"];

				string xml = string.Empty;
				using (var stream = file.OpenReadStream())
				{
					var body = new byte[stream.Length];
					stream.Read(body, 0, body.Length);
					xml = Encoding.UTF8.GetString(body);
				}

				var signedXml = provider.SignSoap(xml, (Mr)mr, thumbprint, password);
				return Ok(signedXml);
			}
			catch (Exception ex)
			{
				return BadRequest($"Ошибка при выполнении запроса: {ex.Message}.");
			}
		}
	}
}