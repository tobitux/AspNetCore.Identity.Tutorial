using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace WebApplication1
{
    public class PluralsightUserClaimsPrincipalFactory
        : UserClaimsPrincipalFactory<PluralsightUser>
    {
        public PluralsightUserClaimsPrincipalFactory(UserManager<PluralsightUser> userManager,
            IOptions<IdentityOptions> optionsAccessor) : base(userManager, optionsAccessor)
        {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(PluralsightUser user)
        {
            var identiy = await base.GenerateClaimsAsync(user);
            identiy.AddClaim(new Claim("locale", user.Locale));
            return identiy;
        }
    }
}