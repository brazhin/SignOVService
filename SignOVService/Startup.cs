using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.SpaServices.Webpack;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
//using SignOVService.Model.Project;
using SignService;

namespace SignOVService
{
	public class Startup
	{
		private ServiceProvider sp;

		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//this.sp = services.BuildServiceProvider();
			//ILoggerFactory loggerFactory = this.sp.GetService<ILoggerFactory>();

			services.AddMvc();
			services.AddTransient<SignServiceProvider>();

			//services.AddSingleton<SignServiceSettings>(fabric => GetSignServiceSettings());

			//services.BuildServiceProvider();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IHostingEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
				app.UseWebpackDevMiddleware(new WebpackDevMiddlewareOptions
				{
					HotModuleReplacement = true,
					ReactHotModuleReplacement = true
				});
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
			}

			app.UseStaticFiles();

			app.UseMvc(routes =>
			{
				routes.MapRoute(
					name: "default",
					template: "{controller=Home}/{action=Index}/{id?}");

				routes.MapSpaFallbackRoute(
					name: "spa-fallback",
					defaults: new { controller = "Home", action = "Index" });
			});
		}

		//private SignServiceSettings GetSignServiceSettings()
		//{
		//	var settings = new SignServiceSettings();
		//	Configuration.GetSection("SignServiceSettings").Bind(settings);

		//	return settings;
		//}
	}
}
