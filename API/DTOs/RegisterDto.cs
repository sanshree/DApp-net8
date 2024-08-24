

using System.ComponentModel.DataAnnotations;

namespace API.DTOs;

public class RegisterDto
{
    [MaxLength(100)]
    public required string username { get; set; }
    public required string password { get; set; }
}
