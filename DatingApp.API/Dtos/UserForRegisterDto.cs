using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Dtos
{
    public class UserForRegisterDto
    {
        [Required]
        public string Username { get; set; }

        [Required]
        [StringLength(16, MinimumLength = 7, ErrorMessage = "The password must be between 7 and 16 characters" )]
        public string Password { get; set; }
    }
}