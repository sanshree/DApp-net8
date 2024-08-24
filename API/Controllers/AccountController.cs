using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context,ITokenService tokenService):BaseApiController
{
    [HttpPost("register")] //account/register
    public async Task<ActionResult<userDto>> Register(RegisterDto registerDto)
    {
        if(await UserExists(registerDto.username))
            return BadRequest("Username is taken");
        
        using var hmac = new HMACSHA512();

        var user = new AppUser
        {
            UserName = registerDto.username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
            PasswordSalt = hmac.Key
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return new userDto{
            Username = user.UserName,
            Token = tokenService.CreateToken(user)
        };
    }

    [HttpPost("login")] //account/login
    public async Task<ActionResult<userDto>> Login(LoginDto loginDto)
    {
        var user = await context.Users.FirstOrDefaultAsync(x => 
        x.UserName == loginDto.username.ToLower());

        if(user == null) return Unauthorized("Invalid username");

        using var hmac = new HMACSHA512(user.PasswordSalt);

        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));

        for(int i=0;i<computedHash.Length;i++)
        {
            if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
        }

        return new userDto
        {
            Username  = user.UserName,
            Token = tokenService.CreateToken(user)
        };
    }

    private async Task<bool> UserExists(string username)
    {
        return await context.Users.AnyAsync(x=>x.UserName.ToLower() == username.ToLower());
    }
    
}