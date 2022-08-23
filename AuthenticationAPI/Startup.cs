using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Mvc.Authorization;
using AuthenticationAPI.Manager;
using AuthenticationAPI.Middleware;

namespace AuthenticationAPI
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        public JwtBearerOptions JwtOptions { get; private set; }
       
        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddSingleton<IMessageManager, Kernel.MessageManager>();
            services.AddSingleton<IQueueManager, Kernel.QueueManager>();
            services.AddSingleton<IObjectManager, Kernel.ObjectManager>();
            //services.AddHostedService<LDAPManager>();
        
            if (Configuration.GetConnectionString("Type") == "My SQL")
            {
                services.AddDbContext<DBContext.MetaDBContext>(options => options.UseMySQL(Configuration.GetConnectionString("DefaultConnection")));
            }
            else
            {
                //  這邊預留處理 MS SQL 的部分, 以後設定在這個地方
            }

            // services.AddScoped<IService, Service.AccountCheckService>();
            // services.AddScoped<IService, Service.MonitorSerialCheckService>();
            services.AddSingleton<ISecurityManager, SecurityManager>();
            services.AddSingleton<IService, Service.HelloService>();

            //0613  建立 CORS  設定.
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder =>
                    {
                        builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                    });
            });

            /*
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,

                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signKey.Key,

                // Validate the token expiry
                ValidateLifetime = true,

                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.FromMinutes(1),
            };*/

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = Configuration["Jwt:Audience"],
                // Validate the token expiry
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:KEY"]))
            };

            this.JwtOptions = new JwtBearerOptions
            {
                TokenValidationParameters = tokenValidationParameters
            };

            services.AddSingleton<JwtBearerOptions>(this.JwtOptions);
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
               .AddJwtBearer(options =>
                 {
                     options.TokenValidationParameters = tokenValidationParameters;
                 });

            services.AddMvc(options =>
            {
                options.Filters.Add(new AuthorizeFilter());
            });

            //--- 偷跑先Run First time avoid User Query Slow ------
            var options = services.BuildServiceProvider().GetRequiredService<DbContextOptions<DBContext.MetaDBContext>>();
            Task.Run(() =>
            {
                using (var dbContext = new DBContext.MetaDBContext(options))
                {
                    dbContext.hellowould.FirstOrDefault();
                }
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            var webSocketOptions = new WebSocketOptions
            {
                KeepAliveInterval = TimeSpan.FromMinutes(2)
            };

          
            app.UseWebSockets(webSocketOptions);
            app.UseMiddleware<WebsocketHandlerMiddleware>();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCors("CorsPolicy");      //0613  建立 CORS  設定.  for angular web connect
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
