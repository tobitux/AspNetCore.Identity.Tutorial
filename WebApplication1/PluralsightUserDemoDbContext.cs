using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1
{
    public class PluralsightUserDemoDbContext : IdentityDbContext<PluralsightUser>
    {
        public PluralsightUserDemoDbContext(DbContextOptions<PluralsightUserDemoDbContext> options) : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<PluralsightUser>(user => user.HasIndex(x => x.Locale).IsUnique(false));

            builder.Entity<Organization>(org =>
            {
                org.ToTable("Organization");
                org.HasKey(x => x.Id);

                org.HasMany<PluralsightUser>().WithOne().HasForeignKey(x => x.OrgId).IsRequired(false);
            });
        }
    }
}
