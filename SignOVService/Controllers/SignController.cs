using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SignOVService.Model;
using SignOVService.Model.Project;
using System;

namespace SignOVService.Controllers
{
	[Route("sign")]
	public class SignController : Controller
	{
		private readonly ILogger<SignController> log;
		private readonly SignServiceSettings settings;

		public SignController(ILogger<SignController> log, SignServiceSettings settings)
		{
			this.log = log;
			this.settings = settings;
		}

		/// <summary>
		/// Метод для тестирования работы сервиса подписания
		/// </summary>
		/// <param name="request"></param>
		/// <returns></returns>
		[HttpPost]
		public IActionResult Post([FromBody] RequestSignOV request, [FromServices] ILoggerFactory loggerFactory)
		{
			try
			{
				log.LogDebug("Получен запрос на подписание.");
				
				log.LogDebug($"MR: {request.Mr}.");
				log.LogDebug($"Thumbprint: {request.Thumbprint}.");

				var signService = new SignOVServiceClient(loggerFactory, settings.StoreLocation, settings.Thumbprint);

				log.LogDebug($"Настройки подписания сервиса: Location: {settings.StoreLocation}, " +
					$"Thumbprint: {settings.Thumbprint}."
				);

				var result = signService.SignOV(request);

				return Ok(result);
			}
			catch (Exception ex)
			{
				log.LogError($"В результате работы метода подписания возникла следующая ошибка: {ex.Message}.");
				return BadRequest(ex.Message);
			}
		}
	}
}