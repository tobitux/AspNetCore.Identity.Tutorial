using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class ForgotPasswordModel
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; }
    }
}