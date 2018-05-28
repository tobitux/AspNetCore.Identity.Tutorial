using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebApplication1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            const string connectionString =
                "Data Source=(LocalDb)\\MSSQLLocalDB;" +
                "database=PluralsightDemo.PluralsightUser;" +
                "trusted_connection=yes;";
            var migrationAssembly =
                typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
            services.AddDbContext<PluralsightUserDemoDbContext>(
                opt => opt.UseSqlServer(connectionString,
                    sql => { sql.MigrationsAssembly(migrationAssembly); }));

            services.AddIdentity<PluralsightUser, IdentityRole>(options =>
                {
                    options.SignIn.RequireConfirmedEmail = true;
                    options.Tokens.EmailConfirmationTokenProvider = "emailconf";

                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequiredLength = 4;

                    options.User.RequireUniqueEmail = true;

                    options.Lockout.AllowedForNewUsers = true;
                    options.Lockout.MaxFailedAccessAttempts = 3;
                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                })
                .AddEntityFrameworkStores<PluralsightUserDemoDbContext>()
                .AddDefaultTokenProviders()
                .AddTokenProvider<
                    EmailConfirmationTokenProvider<PluralsightUser>>(
                    "emailconf")
                .AddPasswordValidator<DoesNotContainPasswordValidator<PluralsightUser>>();

            services.Configure<DataProtectionTokenProviderOptions>(options =>
                options.TokenLifespan = TimeSpan.FromHours(3));
            services.Configure<EmailConfirmationTokenProviderOptions>(options =>
                options.TokenLifespan = TimeSpan.FromDays(2));

            services.AddScoped<IUserClaimsPrincipalFactory<PluralsightUser>,
                PluralsightUserClaimsPrincipalFactory>();

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Home/Login";
            });

            services.AddAuthentication().AddGoogle("google", options =>
            {
                options.ClientId = "";
                options.ClientSecret = "";
                options.SignInScheme = IdentityConstants.ExternalScheme;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}