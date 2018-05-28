using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class TwoFactorModel
    {
        [Required]
        public string Token { get; set; }
    }
}