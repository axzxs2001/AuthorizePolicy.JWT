
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using AuthorizePolicy.JWT;

namespace Token_WebAPI01.Controllers
{
    [Authorize("Permission")]
    public class PermissionController : Controller
    {
        /// <summary>
        /// 自定义策略参数
        /// </summary>
        PermissionRequirement _requirement;
        public PermissionController(IAuthorizationHandler authorizationHander)
        {
            _requirement = (authorizationHander as PermissionHandler).Requirement;
        }
        [AllowAnonymous]
        [HttpPost("/api/login")]
        public IActionResult Login(string username,string password,string role)
        { 
            var isValidated = username == "gsw" && password == "111111";
            if (!isValidated)
            {
                return new JsonResult(new
                {
                    Status = false,
                    Message = "认证失败"
                });
            }
            else
            { 
                //如果是基于角色的授权策略，这里要添加用户;如果是基于角色的授权策略，这里要添加角色
                var claims =new Claim[]{ new Claim(ClaimTypes.Name, username),new Claim(ClaimTypes.Role, role) };
                //用户标识
                var identity = new ClaimsIdentity(JwtBearerDefaults.AuthenticationScheme); 
                identity.AddClaims(claims);
                //登录
                HttpContext.SignInAsync(JwtBearerDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
                var token = JwtToken.BuildJwtToken(claims, _requirement);
                return new JsonResult(token);
            }
        }
        [AllowAnonymous]
        [HttpGet("/api/denied")]
        public IActionResult Denied()
        {
            return new JsonResult(new
            {
                Status = false,
                Message = "你无权限访问"
            });
        }
    }
}
