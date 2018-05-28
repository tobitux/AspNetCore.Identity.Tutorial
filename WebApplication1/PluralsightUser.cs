using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace WebApplication1
{
    public class PluralsightUser : IdentityUser
    {
        public string Locale { get; set; } = "en-GB";

        public string OrgId { get; set; }
    }

    public class Organization
    {
        public string Id { get; set; }

        public string Name { get; set; }
    }
}