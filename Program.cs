using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;
using WebApi.DbContext;
using WebApi.Entities;
using WebApi.Interfaces;
using WebApi.OpenApiSchemeTransformers;
using WebApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Add DB
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    options.UseSqlite(connectionString);
});

// Add Identity
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Config Identity
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.SignIn.RequireConfirmedEmail = false;
});

// Add Authentication and JwtBearer
var validIssuer = builder.Configuration["JWT:ValidIssuer"];
var validAudience = builder.Configuration["JWT:ValidAudience"];
var secret = builder.Configuration["JWT:Secret"];

var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = validIssuer,
            ValidAudience = validAudience,
            IssuerSigningKey = symmetricSecurityKey
        };
    });

var option = 1;

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
if (option == 1)
{
    // option 1: add security scheme only
    builder.Services.AddOpenApi(options =>
    {
        options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
    });
}

if (option == 2)
{
    // option 2: add security scheme and apply it globally
    builder.Services.AddOpenApi("internal", options =>
    {
        options.AddDocumentTransformer<BearerSecuritySchemeTransformer2>();
    });
    builder.Services.AddOpenApi("public");
}

builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    //https://localhost:7052/scalar
    app.MapScalarApiReference(options =>
    {
        //options.AddPreferredSecuritySchemes("BearerAuth"); // Security scheme name from the OpenAPI document
        //options.AddHttpAuthentication("BearerAuth", auth =>
        //{
        //    auth.Token = secret;
        //});
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapGet("/world", () => "Hello world!")
    .WithGroupName("internal");
app.MapGet("/", () => "Hello universe!")
    .WithGroupName("public");

app.MapControllers();

app.Run();
