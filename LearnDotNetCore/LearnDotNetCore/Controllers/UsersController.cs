using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LearnDotNetCore.Context;
using LearnDotNetCore.Migrations;
using LearnDotNetCore.Model;
using LearnDotNetCore.Models;
using LearnDotNetCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly MyContext _context;
        SmtpClient client = new SmtpClient();
        AttrEmail attrEmail = new AttrEmail();
        RandomDigit randDig = new RandomDigit();
        public IConfiguration _configuration;

        public UsersController(MyContext myContext, IConfiguration configuration, IConfiguration config)
        {
            _context = myContext;
            _configuration = configuration;
            _configuration = config;
        }

        // GET api/values
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet]
        //public async Task<List<User>> GetAll()
        public async Task<List<UserVM>> GetAll()
        {
            List<UserVM> list = new List<UserVM>();
            //var user = new UserVM();
            var getData = await _context.RoleUsers.Include("User").Include("Role").ToListAsync();
            if (getData.Count == 0)
            {
                return null;
            }
            foreach (var item in getData)
            {
                var user = new UserVM()
                {
                    Id = item.User.Id,
                    UserName = item.User.UserName,
                    Email = item.User.Email,
                    Password = item.User.PasswordHash,
                    Phone = item.User.PhoneNumber,
                    RoleName = item.Role.Name,
                    VerifyCode = item.User.SecurityStamp,
                };
                list.Add(user);
            }
            return list;
        }

        [HttpGet("{id}")]
        public UserVM GetID(string id)
        {
            var getData = _context.RoleUsers.Include("User").Include("Role").SingleOrDefault(x => x.UserId == id);
            if (getData == null || getData.Role == null || getData.User == null)
            {
                return null;
            }
            var user = new UserVM()
            {
                Id = getData.User.Id,
                UserName = getData.User.UserName,
                Email = getData.User.Email,
                Password = getData.User.PasswordHash,
                Phone = getData.User.PhoneNumber,
                RoleId = getData.Role.Id,
                RoleName = getData.Role.Name
            };
            return user;
        }

        [HttpPost]
        public IActionResult Create(UserVM userVM)
        {
            if (ModelState.IsValid)
            {
                client.Port = 587;
                client.Host = "smtp.gmail.com";
                client.EnableSsl = true;
                client.Timeout = 10000;
                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                client.UseDefaultCredentials = false;
                client.Credentials = new NetworkCredential(attrEmail.mail, attrEmail.pass);

                var code = randDig.GenerateRandom();
                var fill = "Hi " + userVM.UserName + "\n\n"
                          + "Try this Password to get into reset password: \n"
                          + code
                          + "\n\nThank You";

                MailMessage mm = new MailMessage("donotreply@domain.com", userVM.Email, "Create Email", fill);
                mm.BodyEncoding = UTF8Encoding.UTF8;
                mm.DeliveryNotificationOptions = DeliveryNotificationOptions.OnFailure;
                client.Send(mm);

                var user = new User
                {
                    UserName = userVM.UserName,
                    Email = userVM.Email,
                    SecurityStamp = code,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(userVM.Password),
                    PhoneNumber = userVM.Phone,
                    EmailConfirmed = false,
                    PhoneNumberConfirmed = false,
                    TwoFactorEnabled = false,
                    LockoutEnabled = false,
                    AccessFailedCount = 0
                };
                _context.Users.Add(user);
                var uRole = new RoleUser
                {
                    UserId = user.Id,
                    RoleId = "1"
                };
                _context.RoleUsers.Add(uRole);
                var emp = new Employee
                {
                    EmpId = user.Id,
                    CreateTime = DateTimeOffset.Now,
                    IsDelete = false
                };
                _context.Employees.Add(emp);
                _context.SaveChanges();
                return Ok("Successfully Created");
            }
            return BadRequest("Register Failed");
        }

        [HttpPut("{id}")]
        public IActionResult Update(string id, UserVM userVM)
        {
            var getId = _context.Users.Find(id);
            getId.Id = userVM.Id;
            getId.UserName = userVM.UserName;
            getId.Email = userVM.Email;
            var isValid = BCrypt.Net.BCrypt.Verify(userVM.Password, getId.PasswordHash);
            if (isValid) { Ok("Failed Update"); }
            else
            {
                var hasPass = BCrypt.Net.BCrypt.HashPassword(userVM.Password, 12);
                getId.PasswordHash = hasPass;
            }

            getId.PhoneNumber = userVM.Phone;
            var data = _context.Users.Update(getId);
            _context.SaveChanges();
            return Ok("Successfully Update");
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            var getIdr = _context.RoleUsers.Where(g => g.UserId == id).FirstOrDefault();
            var getId = _context.Users.Find(id);
            _context.Users.Remove(getId);
            _context.RoleUsers.Remove(getIdr);
            _context.SaveChanges();
            return Ok("Successfully Delete");
        }

        [HttpPost]
        [Route("login")]
        public IActionResult Login(UserVM userVM)
        {
            if (ModelState.IsValid)
            {
                var getUserRole = _context.RoleUsers.Include("User").Include("Role").SingleOrDefault(x => x.User.Email == userVM.Email);
                if (getUserRole == null)
                {
                    return NotFound();
                }
                else if (userVM.Password == null || userVM.Password.Equals(""))
                {
                    return BadRequest(new { msg = "Password must filled" });
                }
                else if (!BCrypt.Net.BCrypt.Verify(userVM.Password, getUserRole.User.PasswordHash))
                {
                    return BadRequest(new { msg = "Password is Wrong" });
                }
                else
                {
                    if (getUserRole != null)
                    {
                        var user = new UserVM()
                        {
                            Id = getUserRole.User.Id,
                            UserName = getUserRole.User.UserName,
                            Email = getUserRole.User.Email,
                            Password = getUserRole.User.PasswordHash,
                            Phone = getUserRole.User.PhoneNumber,
                            RoleId = getUserRole.Role.Id,
                            RoleName = getUserRole.Role.Name,
                            VerifyCode = getUserRole.User.SecurityStamp,
                        };
                        return Ok(GetJWT(user));
                    }
                    return BadRequest("Invalid credentials");
                }
            }
            return BadRequest("Data Not Valid");
        }

        [HttpPost]
        [Route("code")]
        public IActionResult VerifyCode(UserVM userVM)
        {
            if (ModelState.IsValid)
            {
                var getUserRole = _context.RoleUsers.Include("User").Include("Role").SingleOrDefault(x => x.User.Email == userVM.Email);
                if (getUserRole == null)
                {
                    return NotFound();
                }
                else if (userVM.VerifyCode != getUserRole.User.SecurityStamp)
                {
                    return BadRequest("Your Code is Wrong");
                }
                else
                {
                    getUserRole.User.SecurityStamp = null;
                    _context.SaveChanges();
                    var user = new UserVM()
                    {
                        Id = getUserRole.User.Id,
                        UserName = getUserRole.User.UserName,
                        Email = getUserRole.User.Email,
                        Password = getUserRole.User.PasswordHash,
                        Phone = getUserRole.User.PhoneNumber,
                        RoleId = getUserRole.Role.Id,
                        RoleName = getUserRole.Role.Name,
                        VerifyCode = getUserRole.User.SecurityStamp,
                    };
                    return StatusCode(200, GetJWT(user));
                }
            }
            return BadRequest("Data Not Valid");
        }

        private string GetJWT(UserVM userVM)
        {
            var claims = new List<Claim> {
                            new Claim("Id", userVM.Id),
                            new Claim("UserName", userVM.UserName),
                            new Claim("Email", userVM.Email),
                            new Claim("RoleName", userVM.RoleName),
                            new Claim("VerifyCode", userVM.VerifyCode == null ? "" : userVM.VerifyCode),
                        };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                            _configuration["Jwt:Issuer"],
                            _configuration["Jwt:Audience"],
                            claims,
                            expires: DateTime.UtcNow.AddDays(1),
                            signingCredentials: signIn
                        );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
