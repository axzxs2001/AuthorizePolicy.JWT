# AuthorizePolicy.JWT
A custome policy of authorize standard library for asp.net core 2.0

#### Usage：
###### Starup.cs
        public void ConfigureServices(IServiceCollection services)
        {
            //读取配置文件
            var audienceConfig = Configuration.GetSection("Audience");
            var symmetricKeyAsBase64 = audienceConfig["Secret"];
            var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
            var signingKey = new SymmetricSecurityKey(keyByteArray);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateIssuer = true,
                ValidIssuer = audienceConfig["Issuer"],
                ValidateAudience = true,
                ValidAudience = audienceConfig["Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            //这个集合模拟用户权限表,可从数据库中查询出来
            var permission = new List<Permission> {
                             new Permission {  Url="/", Name="admin"},
                             new Permission {  Url="/api/values", Name="admin"},
                             new Permission {  Url="/", Name="system"},
                             new Permission {  Url="/api/values1", Name="system"}
                          };
              //如果第三个参数，是ClaimTypes.Role，上面集合的每个元素的Name为角色名称，如果ClaimTypes.Name，即上面集合的每个元素的Name为用户名
              var permissionRequirement = new PermissionRequirement("/api/denied", permission, ClaimTypes.Role, audienceConfig["Issuer"], audienceConfig["Audience"], signingCredentials);
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Permission",
                          policy => policy.Requirements.Add(permissionRequirement));
            }).AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                //不使用https
                o.RequireHttpsMetadata = false;
                o.TokenValidationParameters = tokenValidationParameters;
            });
            //注入授权Handler
            services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
            services.AddSingleton(permissionRequirement);
            services.AddMvc();
        }
        
###### PermissionController.cs

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
                   var claims = new Claim[] { new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.Role, role), new Claim(ClaimTypes.Expiration ,DateTime.Now.AddSeconds(_requirement.Expiration.TotalSeconds).ToString())};
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
###### HomeController

    [Authorize(Policy = "Permission")]
    public class HomeController : Controller
