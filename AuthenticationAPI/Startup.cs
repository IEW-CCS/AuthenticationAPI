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
using AuthenticationAPI.DBContext;

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
            services.AddSingleton<ISecurityManager, SecurityManager>();

            services.AddSingleton<IHttpTrxService, Service.APREGREQ_Service>();
            services.AddSingleton<IHttpTrxService, Service.DUUIDRPT_Service>();
            services.AddSingleton<IHttpTrxService, Service.CCREDREQ_Service>();
            services.AddSingleton<IHttpTrxService, Service.APREGCMP_Service>();
            services.AddSingleton<IHttpTrxService, Service.APVRYREQ_Service>();
            services.AddSingleton<IHttpTrxService, Service.APHPWREQ_Service>();
           // services.AddSingleton<ILDAPManagement, Manager.LDAPManager>();

            services.AddSingleton<IHttpTrxService, Service.DUUIDRPT_Service2>();
            services.AddSingleton<IHttpTrxService, Service.CCREDREQ_Service2>();


            //services.AddHostedService<LDAPManager>();
            if (Configuration.GetConnectionString("Provider") =="MY_SQL")
            {
                services.AddDbContext<DBContext.MetaDBContext>(options => options.UseMySQL(Configuration.GetConnectionString("DefaultConnection")));
            }
            else
            {
                //  這邊預留處理 MS SQL 的部分, 以後設定在這個地方
            }

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

            //------- First Run Initial Security Manager ------
            string DBProvider = Configuration.GetConnectionString("Provider");
            string DBConStr = Configuration.GetConnectionString("DefaultConnection");
            var SecurityManager =  app.ApplicationServices.GetService<ISecurityManager>();
            SecurityManager.InitFromDB(DBProvider, DBConStr);

           
            // for LDAP Testing 20220906 
          //  var LDAPManager = app.ApplicationServices.GetService<ILDAPManagement>();
          //  LDAPManager.Init();
          //  bool result = LDAPManager.ModifyUserPassword("james", "James1234");
            



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
